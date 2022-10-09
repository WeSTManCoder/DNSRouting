package main

import (
	. "dnsrouting/configmanager"
	. "dnsrouting/dnsmanager"
	. "dnsrouting/routemanager"
	"dnsrouting/web"
)

func main() {
	Config.Init()
	Route.Init()

	DNSManager.Init()
	DNSManager.SetPort(Config.Port)
	DNSManager.Start()

	web.Start()
}
