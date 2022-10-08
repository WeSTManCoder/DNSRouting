package vpnmanager

import (
	. "dnsrouting/vpnmanager/routemanager"
)

type SVPN struct {
}

var VPN SVPN

func (vpn *SVPN) Init(config string) {
	Route.Init()
}

func (vpn *SVPN) AddToRoute(IPList []string) {
	Route.AddToRoute(IPList)
}
