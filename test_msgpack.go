package main

import (
	"fmt"

	"github.com/vmihailenco/msgpack/v5"
)

type ServerHello struct {
	_msgpack struct{} `msgpack:",asArray"`
	Ok      bool   `msgpack:"ok"`
	Msg     string `msgpack:"msg"`
	Id      uint32 `msgpack:"id"`
	Rx      uint64 `msgpack:"rx"`
	IP      string `msgpack:"ip"`
}

func main() {
	sh := ServerHello{Ok: true, IP: "127.0.0.1"}
	b, _ := msgpack.Marshal(sh)
	
	// Print hex
	fmt.Printf("%x\n", b)
	
	// Unmarshal as interface{}
	var out interface{}
	msgpack.Unmarshal(b, &out)
	fmt.Printf("%#v\n", out)
}
