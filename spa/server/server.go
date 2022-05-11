package spaserver

import (
	"errors"
	"fmt"
	"github.com/1uLang/libspb/encrypt"
	"github.com/1uLang/libspb/iptables"
	"github.com/1uLang/libspb/spa"
	"github.com/fatih/color"
	"log"
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
	IAMcb func(body *spa.Body) (*Allow, error)
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

// Run 启动spa服务
func (c *Server) Run() error {
	if err := c.check(); err != nil {
		return errors.New("config error:" + err.Error())
	}
	//初始化加密通用key,iv
	encrypt.Init(c.KEY, c.IV)
	color.Green("start spa server,listen 0.0.0.0:%d[%s]\n", c.Port, c.Protocol)
	switch c.Protocol {
	case "tcp":
		return c.listenTCP()
	case "udp":
		return c.listenUDP()
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
		c.Port, err = spa.GetPort()
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
func (c *Server) listenTCP() error {

	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", c.Port))
	if err != nil {
		return InvalidConfigPortUse
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go c.handleConn(conn)
	}
}

// tcp服务处理新连接
func (c *Server) handleConn(conn net.Conn) {

	defer conn.Close()
	var buf [1024]byte

	rlen, err := conn.Read(buf[:])
	if err != nil {
		c.print("read tcp failed,err", err)
		return
	}
	c.print("data length:%d,addr:%v", rlen, conn.RemoteAddr().String())
	//解析udp spa 认证包
	body, err := spa.ParsePacket(buf[:rlen])
	if err != nil {
		c.print("parse packet,err", err)
		return
	}
	c.doIAM(body, spa.GetIP(conn.RemoteAddr().String()))
}

// 开启udp服务监听端口
func (c *Server) listenUDP() error {
	listen, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: c.Port})
	if err != nil {
		return err
	}
	defer listen.Close() //关闭监听
	for true {
		var buf [1024]byte
		rlen, addr, err := listen.ReadFromUDP(buf[:]) //接受UDP数据
		if err != nil {
			c.print("read udp failed,err", err)
			continue
		}
		c.print("data length:%d,addr:%v", rlen, addr)

		//解析udp spa 认证包
		body, err := spa.ParsePacket(buf[:rlen])
		if err != nil {
			c.print("parse packet,err", err)
			continue
		}
		c.doIAM(body, addr.IP.String())
	}
	return nil
}

// 进行身份检测
func (c *Server) doIAM(body *spa.Body, ip string) {
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
		if spa.CheckPort(port) {
			err := iptables.OpenAddrPort(ip, "tcp", port, c.Timeout)
			if err != nil {
				c.print("set allow %s err:", ip)
			}
		}
	}
	for _, port := range allow.UdpPorts {
		if spa.CheckPort(port) {
			err := iptables.OpenAddrPort(ip, "udp", port, c.Timeout)
			if err != nil {
				c.print("set allow %s err:", ip)
			}
		}
	}
}
