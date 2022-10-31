package spaserver

import (
	"errors"
	"fmt"
	"github.com/1uLang/libnet"
	"github.com/1uLang/libnet/connection"
	"github.com/1uLang/libnet/options"
	"github.com/1uLang/libspa"
	"github.com/1uLang/libspa/iptables"
	"github.com/fatih/color"
	"net"
	"strings"
)

const (
	magicKey = "f1c8eafb543f03023e97b7be864a4e9b"
)

var (
	InvalidConfigPort    = errors.New("invalid port")
	InvalidConfigPortUse = errors.New("set port occupied")
	InvalidConfigTimeout = errors.New("invalid timeout")
)

type Server struct {
	//加密key
	KEY string
	//加密iv
	IV string
	//协议
	Protocol string
	//监听端口
	Port int
	//测试模式
	Test bool
	//spa 放行时间
	Timeout int
	//spa 身份认证回调
	IAMcb func(body *libspa.Body) (*Allow, error)
}
type Allow struct {
	Enable   bool
	TcpPorts []int
	UdpPorts []int
}

// New 创建spa服务
func New() *Server {
	return &Server{
		Protocol: "udp",
		Timeout:  30,
		KEY:      magicKey,
		IV:       magicKey[:16],
	}
}

// OnConnect 当TCP长连接建立成功是回调
func (c *Server) OnConnect(conn *connection.Connection) {

}

// OnMessage 当客户端有数据写入是回调
func (c *Server) OnMessage(conn *connection.Connection, buf []byte) {
	c.print("data length:%d,addr:%v", len(buf), conn.RemoteAddr())
	//解析udp spa 认证包
	body, err := libspa.ParsePacket(buf)
	if err != nil {
		c.print("parse packet,err", err)
		return
	}
	c.doIAM(body, libspa.GetIP(conn.RemoteAddr()))
}

// OnClose 当客户端主动断开链接或者超时时回调,err返回关闭的原因
func (c *Server) OnClose(conn *connection.Connection, err error) {}

// Run 启动spa服务
func (c *Server) Run(opts ...options.Option) error {
	if err := c.check(); err != nil {
		return errors.New("config error:" + err.Error())
	}
	//初始化加密通用key,iv
	color.Green("start spa server,listen 0.0.0.0:%d[%s]\n", c.Port, c.Protocol)
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
	if c.IAMcb == nil {
		return errors.New("please set spa accept packet auth callback")
	}
	return nil
}

// 打印调试信息
func (c *Server) print(a ...interface{}) {
	if c.Test {
		fmt.Println(a...)
	}
}

// 开启tcp服务监听端口
func (c *Server) listenTCP(opts ...options.Option) error {

	svr, err := libnet.NewServe(fmt.Sprintf(":%d", c.Port), c, opts...)
	if err != nil {
		panic(err)
	}
	err = svr.RunTCP()
	if err != nil {
		panic(err)
	}
	return nil
}

// 开启udp服务监听端口
func (c *Server) listenUDP(opts ...options.Option) error {
	svr, err := libnet.NewServe(fmt.Sprintf(":%d", c.Port), c, opts...)
	if err != nil {
		panic(err)
	}
	err = svr.RunUDP()

	return nil
}

// 进行身份检测
func (c *Server) doIAM(body *libspa.Body, ip string) {
	if c.IAMcb != nil {
		allow, err := c.IAMcb(body)
		if err != nil {
			c.print("do iam callback,err", err)
			return
		}
		if allow != nil && allow.Enable {
			c.doAllow(ip, allow)
		} else {
			c.print("[%s] is block", ip)
		}
	}
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
