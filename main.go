package main

import (
	. "dnsrouting/configmanager"
	. "dnsrouting/dnsmanager"
	. "dnsrouting/routemanager"
	"dnsrouting/web"
	"flag"
)

func main() {
	WorkDir := flag.String("workdir", "/etc/dnsrouting/", "path to files")
	flag.Parse()

	Config.Init(*WorkDir)
	Route.Init()

	DNSManager.Init(*WorkDir)
	DNSManager.SetPort(Config.Port)
	DNSManager.Start()

	web.Start()
}
