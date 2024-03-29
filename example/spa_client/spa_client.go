package main

import (
	"github.com/1uLang/libspa"
	spaclient "github.com/1uLang/libspa/client"
	"github.com/shirou/gopsutil/host"
	"net"
)

func main() {
	cli := spaclient.New()
	cli.Addr = "127.0.0.1"
	cli.Protocol = "udp"
	cli.Port = 54732
	i, err := host.Info()
	if err != nil {
		panic(err)
	}
	err = cli.Send(&libspa.Body{
		ClientDeviceId: i.HostID,
		ServerPublicIP: net.ParseIP("127.0.0.1"),
		ClientPublicIP: net.ParseIP("127.0.0.1"),
	})
	if err != nil {
		panic(err)
	}
}
