package spaserver

import (
	"errors"
	"fmt"
	"github.com/1uLang/libnet"
	"github.com/1uLang/libnet/options"
	"github.com/1uLang/libspa"
	"github.com/1uLang/libspa/iptables"
	log "github.com/sirupsen/logrus"
	"net"
	"strings"
)

var (
	InvalidConfigPort    = errors.New("invalid port")
	InvalidConfigPortUse = errors.New("set port occupied")
	InvalidConfigTimeout = errors.New("invalid timeout")
)

type Server struct {
	//协议
	Protocol string
	//监听端口
	Port int
	//测试模式
	Test bool
	//spa 放行时间
	Timeout int
	options *options.Options
	handler Handler
}
type Allow struct {
	TcpPorts []int
	UdpPorts []int
}

// New 创建spa服务
func New() *Server {
	return &Server{
		Protocol: "udp",
		Timeout:  30,
	}
}

// OnConnect 当TCP长连接建立成功是回调
func (c *Server) OnConnect(conn *libnet.Connection) {
	if c.handler != nil {
		c.handler.OnConnect(conn)
	}
}

// OnMessage 当客户端有数据写入是回调
func (c *Server) OnMessage(conn *libnet.Connection, buf []byte) {
	c.print(fmt.Sprintf("data length:%d,addr:%v", len(buf), conn.RemoteAddr()))
	//解析udp spa 认证包
	if c.handler != nil {
		allow, err := c.handler.OnAuthority(libspa.ParsePacket(buf, c.options.PrivateKey, c.options.PublicKey))
		if err != nil {
			c.print("parse packet,err", err)
			return
		}
		if allow != nil {
			c.doAllow(libspa.GetIP(conn.RemoteAddr()), allow)
		} else {
			c.print("[%s] is block", libspa.GetIP(conn.RemoteAddr()))
		}
	}
}

// OnClose 当客户端主动断开链接或者超时时回调,err返回关闭的原因
func (c *Server) OnClose(conn *libnet.Connection, reason string) {
	if c.handler != nil {
		c.handler.OnClose(conn, errors.New(reason))
	}
}

// Run 启动spa服务
func (c *Server) Run(handler Handler, opts ...options.Option) error {
	if err := c.check(); err != nil {
		return errors.New("config error:" + err.Error())
	}
	c.handler = handler
	c.options = options.GetOptions(opts...)
	//初始化加密通用key,iv
	switch c.Protocol {
	case "tcp":
		return c.listenTCP(opts...)
	case "udp":
		return c.listenUDP(opts...)
	}
	return nil
}

// 检测配置是否正确
func (c *Server) check() (err error) {
	c.Protocol = strings.ToLower(c.Protocol)
	if c.Protocol != "tcp" && c.Protocol != "udp" {
		return errors.New("please set server protocol tcp or udp")
	}
	if c.Port < 0 {
		return InvalidConfigPort
	}
	if c.Port == 0 {
		//未设置端口随机设置一个未暂用的端口
		c.Port, err = libspa.GetPort()
		if err != nil {
			return errors.New("random set listen port error:" + err.Error())
		}
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", c.Port))
	if err != nil {
		return InvalidConfigPortUse
	}
	ln.Close()
	if c.Timeout <= 0 {
		return InvalidConfigTimeout
	}
	if c.Test {
		log.SetLevel(log.DebugLevel)
	}
	return nil
}

// 打印调试信息
func (c *Server) print(a ...interface{}) {
	log.Debug(a...)
}

// 开启tcp服务监听端口
func (c *Server) listenTCP(opts ...options.Option) error {
	return libnet.NewServe(fmt.Sprintf(":%d", c.Port), c, opts...).RunTCP()
}

// 开启udp服务监听端口
func (c *Server) listenUDP(opts ...options.Option) error {
	return libnet.NewServe(fmt.Sprintf(":%d", c.Port), c, opts...).RunUDP()
}

// 设置IP放行
func (c *Server) doAllow(ip string, allow *Allow) {
	for _, port := range allow.TcpPorts {
		if libspa.CheckPort(port) {
			err := iptables.OpenAddrPort(ip, "tcp", port, c.Timeout)
			if err != nil {
				c.print("set allow %s err:", ip)
			}
		}
	}
	for _, port := range allow.UdpPorts {
		if libspa.CheckPort(port) {
			err := iptables.OpenAddrPort(ip, "udp", port, c.Timeout)
			if err != nil {
				c.print("set allow %s err:", ip)
			}
		}
	}
}
