package spaserver

import (
	"github.com/1uLang/libnet"
	"github.com/1uLang/libspa"
)

type Handler interface {
	OnConnect(conn *libnet.Connection)
	OnAuthority(body *libspa.Body, err error) (*Allow, error)
	OnClose(conn *libnet.Connection, err error)
}
