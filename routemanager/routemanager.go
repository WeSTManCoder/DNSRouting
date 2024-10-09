package routemanager

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	. "dnsrouting/configmanager"

	netlink "github.com/vishvananda/netlink"
	nl "github.com/vishvananda/netlink/nl"
)

type RouteInterface struct {
	NLHandle *netlink.Handle
	DevLink  netlink.Link
}

var Route RouteInterface

func (r *RouteInterface) RouteListUpdate() {
	time.Sleep(60 * time.Second)

	for true {
		file, err := os.Open(fmt.Sprintf("%sservices.txt", Config.WorkDir))
		if err != nil {
			fmt.Printf("Fail load %sservices.txt with error: %s\n", Config.WorkDir, err.Error())
			os.Exit(1)
		}

		scanner := bufio.NewScanner(file)

		var IPFileList []string

		for scanner.Scan() {
			Line := scanner.Text()
			if len(Line) <= 2 || strings.Contains(Line, "//") {
				continue
			}

			matched, err := regexp.MatchString("\\d+\\.\\d+\\.\\d+\\.\\d+(\\/\\d+)?", Line)
			if err != nil {
				fmt.Println("Error:", err)
			}

			if matched {
				IPFileList = append(IPFileList, Line)
			}

		}

		if err := scanner.Err(); err != nil {
			fmt.Println("Scanner with error:", err)
		}

		file.Close()

		r.AddToRoute(IPFileList)

		time.Sleep(60 * time.Second)
	}
}

func (r *RouteInterface) Init() {
	NetLinkHandle, err := netlink.NewHandle(nl.FAMILY_V4)
	if err != nil {
		fmt.Println("netlink err:", err.Error())
		os.Exit(1)
	}
	r.NLHandle = NetLinkHandle

	go r.RouteListUpdate()
}

// Измененная функция для возврата списка подсетей (*net.IPNet)
func (r *RouteInterface) GetIPRouteList() ([]*net.IPNet, error) {
	var IPList []*net.IPNet
	VPNInterface, err := r.NLHandle.LinkByName(Config.VPNInterface)
	if err != nil {
		fmt.Printf("No found %s with error: %s\n", Config.VPNInterface, err.Error())
		return IPList, err
	}
	r.DevLink = VPNInterface

	NLRouteList, err := r.NLHandle.RouteList(VPNInterface, nl.FAMILY_V4)
	if err != nil {
		fmt.Println(err)
		return IPList, err
	}

	for i := range NLRouteList {
		// Добавляем подсети в IPList
		if NLRouteList[i].Dst != nil {
			IPList = append(IPList, NLRouteList[i].Dst)
		}
	}

	return IPList, nil
}

// Функция добавления IP-адресов в маршрут
func (r *RouteInterface) AddToRoute(IPList []string) {
	IPListInRoute, err := r.GetIPRouteList() // Получаем список подсетей
	if err != nil {
		fmt.Println("Fail add IP to route:", err.Error())
		return
	}

	for _, ip := range IPList {
		// Если маска отсутствует, добавляем маску /32
		if !strings.Contains(ip, "/") {
			ip += "/32"
		}

		// Парсим IP и CIDR
		parsedIP, _, err := net.ParseCIDR(ip)
		if err != nil {
			fmt.Println("Failed to parse IP:", err.Error())
			continue
		}

		// Проверяем, находится ли IP в одной из подсетей
		HasExist := IPInList(parsedIP, IPListInRoute)

		if !HasExist {
			_, ipnet, _ := net.ParseCIDR(ip)
			NLRoute := &netlink.Route{
				LinkIndex: r.DevLink.Attrs().Index,
				Dst:       ipnet,
				Scope:     netlink.SCOPE_LINK,
				Table:     254,
			}
			err := r.NLHandle.RouteAdd(NLRoute)
			if err != nil {
				fmt.Println("Fail add route:", err.Error())
			}
		}
	}
}

// Измененная функция для проверки, входит ли IP в подсеть
func IPInList(ip net.IP, IPList []*net.IPNet) bool {
	for _, ipNet := range IPList {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}
