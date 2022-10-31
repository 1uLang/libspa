package spaserver

import (
	"github.com/1uLang/libnet/connection"
	"github.com/1uLang/libspa"
)

type Handler interface {
	OnConnect(conn *connection.Connection)
	OnAuthority(body *libspa.Body, err error) (*Allow, error)
	OnClose(conn *connection.Connection, err error)
}
