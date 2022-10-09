package dnsmanager

import (
	"bufio"
	"context"
	. "dnsrouting/configmanager"
	. "dnsrouting/routemanager"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type SDNSManager struct {
	UDPSock      net.PacketConn
	Port         int
	DNSServers   []string
	DNSList      []dns.Msg
	DNSRegexList []string
	mutex        sync.Mutex
}

var DNSManager SDNSManager

func (DNSManager *SDNSManager) Init() {
	DNSManager.LoadDNSRegexList()
	DNSManager.InitDNSServers()
}

func (DNSManager *SDNSManager) InitDNSServers() {
	DNSManager.DNSServers = strings.Split(Config.DNSServerList, ";")
}

func (DNSManager *SDNSManager) SetPort(Port int) {
	DNSManager.Port = Port
}

func (DNSManager *SDNSManager) Start() {
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", DNSManager.Port))
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	DNSManager.UDPSock = conn
	go DNSManager.MainUDPHandler()
	go DNSManager.UpdateCacheLoop()
}

func (DNSManager *SDNSManager) MainUDPHandler() {
	fmt.Println("Start UDP Handler on port", DNSManager.Port)
	defer DNSManager.UDPSock.Close()
	for {
		buf := make([]byte, 1024)
		n, addr, err := DNSManager.UDPSock.ReadFrom(buf)
		if err != nil {
			fmt.Println(err)
			return
		}

		if n <= 0 {
			continue
		}

		go DNSManager.Handler(addr, buf)
	}
}

func (DNSManager *SDNSManager) Handler(addr net.Addr, buf []byte) {
	DNSRequest := dns.Msg{}
	err := DNSRequest.Unpack(buf)
	if err != nil {
		fmt.Printf("Failed decode binary to DNS Message: %s\n", err.Error())
		return
	}

	domain := DNSManager.GetDomain(&DNSRequest)
	if DNSManager.IsDomainMatch(domain) {
		DNSManager.mutex.Lock()
		DNSAnswer, HasCache := DNSManager.IsCache(domain)

		if HasCache {
			DNSManager.mutex.Unlock()
			DNSManager.AddToRoute(&DNSAnswer)
			DNSAnswer.Id = DNSRequest.Id
			buffer, _ := DNSAnswer.Pack()
			DNSManager.UDPSock.WriteTo(buffer, addr)

			return
		}

		DNSAnswer, err := DNSManager.GetDNSFromHTTP(domain)
		if err == nil && len(DNSAnswer.Answer) > 0 {
			DNSManager.AddCache(DNSAnswer)
			DNSManager.mutex.Unlock()
			DNSAnswer.Id = DNSRequest.Id

			answer, _ := DNSAnswer.Pack()
			DNSManager.UDPSock.WriteTo(answer, addr)

			return
		}
		DNSManager.mutex.Unlock()
	}

	DNSAnswer := DNSManager.GetDNSFromDNSServer(&DNSRequest)
	answer, err := DNSAnswer.Pack()
	if err != nil {
		fmt.Println("Fail pack DNSAnswer with error:", err.Error())
		return
	}
	DNSManager.UDPSock.WriteTo(answer, addr)
}

func (DNSManager *SDNSManager) LoadDNSRegexList() {
	file, err := os.Open("services.txt")
	if err != nil {
		fmt.Printf("Fail load services.txt with error: %s\n", err.Error())
		os.Exit(1)
	}

	defer file.Close()
	scanner := bufio.NewScanner(file)

	DNSManager.DNSRegexList = nil

	for scanner.Scan() {
		Line := scanner.Text()
		if len(Line) <= 2 || strings.Contains(Line, "//") {
			continue
		}

		DNSManager.DNSRegexList = append(DNSManager.DNSRegexList, Line)
		fmt.Println("Regex:", Line)
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Scanner with error:", err)
	}
}

func (DNSManager *SDNSManager) IsDomainMatch(domain string) bool {
	for _, regex := range DNSManager.DNSRegexList {
		matched, err := regexp.MatchString(regex, domain)
		if err != nil {
			fmt.Println("Error:", err)
		}

		if matched {
			return true
		}
	}

	return false
}

func (DNSManager *SDNSManager) GetDomain(DNSRecord *dns.Msg) string {
	DNSDomain := DNSRecord.Question[0].Name
	DNSDomain = DNSDomain[:len(DNSDomain)-1]

	return DNSDomain
}

func (DNSManager *SDNSManager) IsCache(domain string) (dns.Msg, bool) {
	for _, DNSRecord := range DNSManager.DNSList {
		DNSDomain := DNSManager.GetDomain(&DNSRecord)

		if strings.Compare(DNSDomain, domain) == 0 {
			return DNSRecord, true
		}
	}

	return dns.Msg{}, false
}

func (DNSManager *SDNSManager) AddCache(DNSRecord dns.Msg) {
	DNSManager.DNSList = append(DNSManager.DNSList, DNSRecord)
	DNSManager.AddToRoute(&DNSRecord)
}

func (DNSManager *SDNSManager) AddToRoute(DNSRecord *dns.Msg) {
	var IPList []string
	for i := range DNSRecord.Answer {
		if DNSRecord.Answer[i].Header().Rrtype == dns.TypeA {
			IPList = append(IPList, DNSRecord.Answer[i].(*dns.A).A.String())
		}
	}
	if len(IPList) > 0 {
		Route.AddToRoute(IPList)
	}
}

func (DNSManager *SDNSManager) UpdateCacheLoop() {
	for {
		time.Sleep(time.Duration(Config.DNSCacheRefresh) * time.Second)

		for i, DNSRecord := range DNSManager.DNSList {
			domain := DNSManager.GetDomain(&DNSRecord)
			fmt.Printf("Start update domian: %s\n", domain)
			DNSAnswer, err := DNSManager.GetDNSFromHTTP(domain)
			if err != nil {
				fmt.Printf("Failed update %s with error: %s\n", domain, err.Error())
				continue
			}

			DNSManager.DNSList[i] = DNSAnswer
			DNSManager.AddToRoute(&DNSAnswer)

			time.Sleep(500 * time.Millisecond)
		}

		fmt.Println("Cache updated")
	}
}

func (DNSManager *SDNSManager) GetDNSFromDNSServer(DNSRequest *dns.Msg) dns.Msg {
	var DNSServer string
	if len(DNSManager.DNSServers) > 1 {
		DNSServer = DNSManager.DNSServers[rand.Intn(len(DNSManager.DNSServers)-1)] + ":53"
	} else {
		DNSServer = DNSManager.DNSServers[0] + ":53"
	}
	conn, errdial := net.Dial("udp4", DNSServer)
	conn.SetDeadline(time.Now().Add(time.Duration(Config.DNSTimeout) * time.Second))
	if errdial != nil {
		fmt.Printf("Failed LocalDNS %s with error %s\n", DNSManager.GetDomain(DNSRequest), errdial.Error())
		return *DNSRequest
	}

	defer conn.Close()
	buf, err := DNSRequest.Pack()
	if err != nil {
		fmt.Printf("Failed DNSRequest pack with error %s\n", errdial.Error())
		return *DNSRequest
	}
	_, errw := conn.Write(buf)
	if errw != nil {
		fmt.Printf("Failed write to DNS with error: %s\n", errw.Error())
		return *DNSRequest
	}

	ReadBuf := make([]byte, 1024)
	n, err := conn.Read(ReadBuf)
	if n <= 0 || err != nil {
		//fmt.Printf("Failed DNS (domain %s) with error: %s\n", DNSManager.GetDomain(DNSRequest), err.Error())
		return *DNSRequest
	}

	DNSAnswer := dns.Msg{}
	errpack := DNSAnswer.Unpack(ReadBuf)
	if errpack != nil {
		//fmt.Printf("Failed to parse DNS with error: %s\n", errpack.Error())
		return *DNSRequest
	}

	return DNSAnswer
}

func (DNSManager *SDNSManager) GetDNSFromHTTP(domain string) (dns.Msg, error) {
	dialer := &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Duration(Config.DNSTimeout) * time.Second,
				}
				if len(DNSManager.DNSServers) > 1 {
					return d.DialContext(ctx, "udp", DNSManager.DNSServers[rand.Intn(len(DNSManager.DNSServers)-1)]+":53")
				}

				return d.DialContext(ctx, "udp", DNSManager.DNSServers[0]+":53")
			},
		},
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	http.DefaultTransport.(*http.Transport).DialContext = dialContext

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/resolve?name=%s&ct=application/dns-message", Config.DoHServer, domain), nil)
	if err != nil {
		return dns.Msg{}, err
	}

	client := &http.Client{}
	client.Timeout = time.Duration(Config.DNSTimeout) * time.Second
	resp, err := client.Do(req)

	if err != nil {
		return dns.Msg{}, err
	}

	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	DNSAnswer := dns.Msg{}
	DNSAnswer.Unpack(body)

	return DNSAnswer, nil
}
