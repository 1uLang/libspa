package spaserver

import (
	"errors"
	"fmt"
	"github.com/1uLang/libnet"
	"github.com/1uLang/libnet/options"
	"github.com/1uLang/libspa"
	"github.com/1uLang/libspa/iptables"
	log "github.com/sirupsen/logrus"
)

// 处理 通信的handler
type handler struct {
	//spa 放行时间
	timeout int
	handler Handler
	options *options.Options
}

// OnConnect 当TCP长连接建立成功是回调
func (c *handler) OnConnect(conn *libnet.Connection) {
	if c.handler != nil {
		c.handler.OnConnect(conn)
	}
}

// OnMessage 当客户端有数据写入是回调
func (c *handler) OnMessage(conn *libnet.Connection, buf []byte) {
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
func (c *handler) OnClose(conn *libnet.Connection, reason string) {
	if c.handler != nil {
		c.handler.OnClose(conn, errors.New(reason))
	}
}

// 设置IP放行
func (c *handler) doAllow(ip string, allow *Allow) {
	for _, port := range allow.TcpPorts {
		if libspa.CheckPort(port) {
			err := iptables.OpenAddrPort(ip, "tcp", port, c.timeout)
			if err != nil {
				c.print("set allow %s err:", ip)
			}
		}
	}
	for _, port := range allow.UdpPorts {
		if libspa.CheckPort(port) {
			err := iptables.OpenAddrPort(ip, "udp", port, c.timeout)
			if err != nil {
				c.print("set allow %s err:", ip)
			}
		}
	}
}

// 打印调试信息
func (c *handler) print(a ...interface{}) {
	log.Debug(a...)
}
