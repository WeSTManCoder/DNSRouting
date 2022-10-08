package main

import (
	. "dnsrouting/configmanager"
	. "dnsrouting/dnsmanager"
	. "dnsrouting/vpnmanager"
	"dnsrouting/web"
)

func main() {
	Config.Init()
	go VPN.Init("/tmp/vpnconfig.ovpn")

	DNSManager.Init()
	DNSManager.SetPort(Config.Port)
	DNSManager.Start()

	web.Start()
}
