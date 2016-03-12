package main

import (
	"flag"
	"log"

	"github.com/remind101/dnsdog"
)

func main() {
	var (
		iface = flag.String("iface", "eth0", "Interface to listen on")
		addr  = flag.String("statsd", "127.0.0.1:8125", "Statsd address")
	)
	flag.Parse()
	if err := dnsdog.Watch(*iface, *addr); err != nil {
		log.Fatal(err)
	}
}
