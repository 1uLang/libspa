package spaserver

import (
	"github.com/1uLang/libnet"
	"github.com/1uLang/libspa"
)

// Handler 处理spa服务的handler
type Handler interface {
	OnConnect(conn *libnet.Connection)                        // 新连接回调
	OnAuthority(body *libspa.Body, err error) (*Allow, error) //设备认证回调
	OnClose(conn *libnet.Connection, err error)               // 连接断开回调
}
