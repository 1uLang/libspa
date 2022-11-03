package spaserver

import (
	"errors"
	"fmt"
	"github.com/1uLang/libnet"
	"github.com/1uLang/libnet/options"
	"github.com/1uLang/libspa"
	"github.com/1uLang/libspa/encrypt"
	log "github.com/sirupsen/logrus"
	"net"
	"strings"
	"time"
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
	//加密方式
	Method string
	//协议
	Protocol string
	//监听端口
	Port int
	//测试模式
	Test bool
	//spa 放行时间
	SPATimeout int
	//读超时时间
	RawTimeout int
	//连接处理接口
	handler Handler

	options *options.Options
	method  encrypt.MethodInterface
}

type Allow struct {
	TcpPorts []int
	UdpPorts []int
}

// New 创建spa服务
func New() *Server {
	return &Server{
		Protocol:   "udp",
		SPATimeout: 30,
	}
}

// Run 启动spa服务
func (c *Server) Run() error {
	if err := c.check(); err != nil {
		return errors.New("config error:" + err.Error())
	}

	opts := []options.Option{}
	if c.method != nil {
		opts = append(opts, options.WithEncryptMethod(c.method),
			options.WithPrivateKey([]byte(c.KEY)),
			options.WithPublicKey([]byte(c.IV)))
		if c.RawTimeout > 0 {
			opts = append(opts, options.WithTimeout(time.Duration(c.RawTimeout)))
		}
	}
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

// SetHandler 设置连接处理接口
func (c *Server) SetHandler(h Handler) {
	c.handler = h
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
	if c.SPATimeout <= 0 {
		return InvalidConfigTimeout
	}
	if c.Method != "" {
		c.method, err = encrypt.NewMethodInstance(c.Method, c.KEY, c.IV)
		if err != nil {
			return err
		}
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
	return libnet.NewServe(fmt.Sprintf(":%d", c.Port), &handler{timeout: c.SPATimeout, handler: c.handler, options: c.options}, opts...).RunTCP()
}

// 开启udp服务监听端口
func (c *Server) listenUDP(opts ...options.Option) error {
	return libnet.NewServe(fmt.Sprintf(":%d", c.Port), &handler{timeout: c.SPATimeout, handler: c.handler, options: c.options}, opts...).RunUDP()
}
