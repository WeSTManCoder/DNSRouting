package routemanager

import (
	"fmt"
	"net"
	"os"

	. "dnsrouting/configmanager"

	netlink "github.com/vishvananda/netlink"
	nl "github.com/vishvananda/netlink/nl"
)

type RouteInterface struct {
	NLHandle *netlink.Handle
	DevLink  netlink.Link
}

var Route RouteInterface

func (r *RouteInterface) Init() {
	NetLinkHandle, err := netlink.NewHandle(nl.FAMILY_V4)
	if err != nil {
		fmt.Println("netlink err:", err.Error())
		os.Exit(1)
	}
	r.NLHandle = NetLinkHandle
}

func (r *RouteInterface) GetIPRouteList() ([]string, error) {
	var IPList []string
	tun0, err := r.NLHandle.LinkByName(Config.VPNInterface)
	if err != nil {
		fmt.Printf("No found tun0 with error: %s", err.Error())
		return IPList, err
	}
	r.DevLink = tun0
	NLRouteList, err := r.NLHandle.RouteList(tun0, nl.FAMILY_V4)
	if err != nil {
		fmt.Println(err)
		return IPList, err
	}

	for i := range NLRouteList {
		IPList = append(IPList, NLRouteList[i].Dst.IP.String())
	}

	return IPList, nil
}

func (r *RouteInterface) AddToRoute(IPList []string) {
	IPListInRoute, err := Route.GetIPRouteList()
	if err != nil {
		fmt.Println("Fail add ip to route:", err.Error())
		return
	}

	for _, ip := range IPList {
		HasExist := IPInList(ip, IPListInRoute)

		if !HasExist {
			_, ipnet, _ := net.ParseCIDR(ip + "/32")
			NLRoute := &netlink.Route{LinkIndex: r.DevLink.Attrs().Index, Dst: ipnet, Scope: netlink.SCOPE_LINK, Table: 254}
			err := r.NLHandle.RouteAdd(NLRoute)
			if err != nil {
				fmt.Println("Fail add route:", err.Error())
			}
		}
	}
}

func IPInList(ip string, IPList []string) bool {
	for i := range IPList {
		if ip == IPList[i] {
			return true
		}
	}

	return false
}
