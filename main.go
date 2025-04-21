package main

import (
	. "dnsrouting/configmanager"
	. "dnsrouting/dnsmanager"
	. "dnsrouting/routemanager"
	"dnsrouting/web"
	"flag"
	"fmt"
)

const Version = "1.0.4"

func main() {
	fmt.Println("[DNSRouting] version:", Version)
	fmt.Println("[DNSRouting] Author: WeSTMan | VK: https://vk.com/id55942612")

	WorkDir := flag.String("workdir", "/etc/config/dnsrouting/", "path to files")
	flag.Parse()

	Config.Init(*WorkDir)
	Route.Init()

	DNSManager.Init()
	DNSManager.SetPort(Config.Port)
	DNSManager.Start()

	web.Start()
}
