package main

import (
	"fmt"
	"github.com/1uLang/libspa"
	spaserver "github.com/1uLang/libspa/server"
)

func main() {
	srv := spaserver.New()
	srv.IAMcb = func(body *libspa.Body) (*spaserver.Allow, error) {
		fmt.Println("==== new body", *body)
		return nil, nil
	}
	srv.Run()
}
