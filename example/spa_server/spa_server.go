package main

import (
	spaserver "github.com/1uLang/libspa/server"
)

func main() {
	srv := spaserver.New()
	srv.Run(nil)
}
