package spaclient

import (
	"fmt"
	"github.com/1uLang/libnet"
	"github.com/1uLang/libspa"
	"github.com/1uLang/libspa/encrypt"
	"github.com/pkg/errors"
	"strings"
)

const (
	magicKey = "f1c8eafb543f03023e97b7be864a4e9b"
)

var (
	InvalidConfigPort         = errors.New("invalid port")
	SPAEncryptMethodRAW       = "raw"
	SPAEncryptMethodAES128CFB = "aes-128-cfb"
	SPAEncryptMethodAES192CFB = "aes-192-cfb"
	SPAEncryptMethodAES256CFB = "aes-256-cfb"
	encryptMethodGMSM2ECC     = "gm-sm2-ecc"
	encryptMethodGMSM3SUM     = "gm-sm3-sum"
	encryptMethodGMSM4CBC     = "gm-sm4-cbc"
)

type Client struct {
	//加密key
	KEY string
	//加密iv
	IV string
	//加密方式
	Method string
	//协议
	Protocol string
	//服务器端口
	Port int
	//服务器地址
	Addr string
	//测试模式
	Test   bool
	method encrypt.MethodInterface
}

func New() *Client {
	return &Client{
		KEY:    magicKey,
		IV:     magicKey[:16],
		Method: SPAEncryptMethodAES256CFB,
	}
}
func (c *Client) Send(body *libspa.Body) (err error) {

	if err := c.check(); err != nil {
		return errors.New("config error:" + err.Error())
	}
	//初始化加密通用key,iv

	switch c.Protocol {
	case "tcp":
		return c.connectTCP(body)
	case "udp":
		return c.connectUDP(body)
	}
	return nil
}

// 检测配置是否正确
func (c *Client) check() error {
	c.Protocol = strings.ToLower(c.Protocol)
	if c.Protocol != "tcp" && c.Protocol != "udp" {
		return errors.New("please set server protocol tcp or udp")
	}
	if !libspa.CheckPort(c.Port) {
		return InvalidConfigPort
	}
	if c.Addr == "" {
		return errors.New("please set spa server addr")
	}
	return nil
}

// 打印调试信息
func (c *Client) print(a ...interface{}) {
	if c.Test {
		fmt.Println(a...)
	}
}

// 连接tcp服务
func (c *Client) connectTCP(body *libspa.Body) error {
	conn, err := libnet.NewClient(fmt.Sprintf("%s:%d", c.Addr, c.Port), nil)
	if err != nil {
		c.print("connect tcp server,err", err)
		return err
	}
	defer conn.Close()
	bytes, err := libspa.NewPacket(body, c.method)
	if err != nil {
		c.print("new spa packet,err", err)
		return err
	}
	_, err = conn.Write(bytes)
	if err != nil {
		c.print("send spa packet,err", err)
		return err
	}
	return nil
}

// 连接udp服务
func (c *Client) connectUDP(body *libspa.Body) error {
	conn, err := libnet.NewClient(fmt.Sprintf("%s:%d", c.Addr, c.Port), nil)
	if err != nil {
		c.print("connect udp server,err", err)
		return err
	}
	defer conn.Close() //关闭连接
	bytes, err := libspa.NewPacket(body, c.method)
	if err != nil {
		c.print("new spa packet,err", err)
		return err
	}
	_, err = conn.Write(bytes)
	if err != nil {
		c.print("send spa packet,err", err)
		return err
	}
	return nil
}
