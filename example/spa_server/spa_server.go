package main

import (
	"fmt"
	"github.com/1uLang/libspb/spa"
	spaserver "github.com/1uLang/libspb/spa/server"
)

func main() {
	srv := spaserver.New()
	srv.IAMcb = func(body *spa.Body) (*spaserver.Allow, error) {
		fmt.Println("==== new body", *body)
		return nil, nil
	}
	srv.Run()
}
