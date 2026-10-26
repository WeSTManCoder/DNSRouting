package dnsmanager

import (
	"bufio"
	"bytes"
	. "dnsrouting/adguardmanager"
	. "dnsrouting/configmanager"
	. "dnsrouting/routemanager"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type SDNSManager struct {
	UDPSock          net.PacketConn
	Port             int
	DNSServers       []string
	DNSList          []dns.Msg
	DNSOnlyList      []dns.Msg // Отдельный кеш только для DoH-only
	DNSRegexList     []string
	DNSOnlyRegexList []string
	mutex            sync.Mutex
	cacheVersion     uint64
}

var DNSManager SDNSManager

func (DNSManager *SDNSManager) Init() {
	DNSManager.LoadDNSRegexList()
	DNSManager.LoadDNSOnlyRegexList()
	DNSManager.InitDNSServers()
}

func (DNSManager *SDNSManager) InitDNSServers() {
	servers := splitServers(Config.DNSServerList)
	DNSManager.mutex.Lock()
	DNSManager.DNSServers = servers
	DNSManager.mutex.Unlock()
}

func splitServers(value string) []string {
	var servers []string
	for _, server := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ';' || r == '\n' || r == '\r'
	}) {
		if server = strings.TrimSpace(server); server != "" {
			servers = append(servers, server)
		}
	}
	return servers
}

func (DNSManager *SDNSManager) ServerSnapshot() []string {
	DNSManager.mutex.Lock()
	defer DNSManager.mutex.Unlock()
	return append([]string(nil), DNSManager.DNSServers...)
}

// Приоритет режимов: маршрутизируемые домены, затем DoH-only, затем стандартный DNS.
func (DNSManager *SDNSManager) domainMode(domain string) (route bool, dohOnly bool) {
	DNSManager.mutex.Lock()
	defer DNSManager.mutex.Unlock()

	for _, pattern := range DNSManager.DNSRegexList {
		if ok, _ := regexp.MatchString(pattern, domain); ok {
			return true, false
		}
	}

	for _, pattern := range DNSManager.DNSOnlyRegexList {
		if ok, _ := regexp.MatchString(pattern, domain); ok {
			return false, true
		}
	}

	return false, false
}

func (DNSManager *SDNSManager) LoadDNSOnlyRegexList() {
	entries := readRegexFile(Config.WorkDir + "doh-only.txt")
	DNSManager.mutex.Lock()
	DNSManager.DNSOnlyRegexList = entries
	DNSManager.mutex.Unlock()
}

func readRegexFile(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Printf("Failed to read %s: %v\n", path, err)
		}
		return nil
	}
	defer file.Close()

	var result []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if len(line) <= 2 ||
			strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "//") {
			continue
		}

		if net.ParseIP(line) != nil {
			continue
		}

		if _, err := regexp.Compile(line); err != nil {
			fmt.Printf("Invalid regex %q in %s: %v\n", line, path, err)
			continue
		}

		result = append(result, line)
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Regex scanner %s: %v\n", path, err)
	}

	return result
}

func (DNSManager *SDNSManager) SetPort(Port int) {
	DNSManager.Port = Port
}

func (DNSManager *SDNSManager) Start() {
	conn, err := net.ListenPacket(
		"udp",
		fmt.Sprintf(":%d", DNSManager.Port),
	)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	DNSManager.UDPSock = conn

	go DNSManager.MainUDPHandler()
	go DNSManager.UpdateCacheLoop()
	go DNSManager.UpdateDoHOnlyCacheLoop()
	go DNSManager.RestoreCachedRoutesLoop()
}

func (DNSManager *SDNSManager) MainUDPHandler() {
	fmt.Println("Start UDP Handler on port", DNSManager.Port)
	defer DNSManager.UDPSock.Close()

	for {
		buf := make([]byte, 65535)

		n, addr, err := DNSManager.UDPSock.ReadFrom(buf)
		if err != nil {
			fmt.Println(err)
			return
		}

		if n <= 0 {
			continue
		}

		// Каждый входящий DNS-запрос обрабатывается
		// в отдельной goroutine.
		go DNSManager.Handler(addr, buf[:n])
	}
}

func (DNSManager *SDNSManager) Handler(
	addr net.Addr,
	buf []byte,
) {
	DNSRequest := dns.Msg{}

	err := DNSRequest.Unpack(buf)
	if err != nil {
		fmt.Printf(
			"Failed decode binary to DNS Message: %s\n",
			err.Error(),
		)
		return
	}

	domain := DNSManager.GetDomain(&DNSRequest)

	routeDomain, dohOnlyDomain := DNSManager.domainMode(domain)

	if routeDomain || dohOnlyDomain {
		if Config.Debug {
			fmt.Printf(
				"[DEBUG] Domain %s in dnsrouting list\n",
				domain,
			)
		}

		// Для маршрутизируемых доменов используется DNSList.
		// Для DoH-only используется отдельный DNSOnlyList.
		if Config.EnableCache {
			var DNSAnswer dns.Msg
			var HasCache bool

			if routeDomain {
				DNSAnswer, HasCache = DNSManager.IsCache(
					domain,
					&DNSRequest,
				)
			} else {
				DNSAnswer, HasCache = DNSManager.IsDoHOnlyCache(
					domain,
					&DNSRequest,
				)
			}

			if HasCache {
				if Config.Debug {
					fmt.Printf(
						"[DEBUG] Domain %s is in cache\n",
						domain,
					)
				}

				// Только основной кеш добавляет маршруты.
				if routeDomain {
					DNSManager.AddToRoute(&DNSAnswer)
				}

				DNSAnswer.Id = DNSRequest.Id

				buffer, err := DNSAnswer.Pack()
				if err != nil {
					fmt.Println(
						"Failed pack cached DNS response:",
						err,
					)
					return
				}

				DNSManager.UDPSock.WriteTo(buffer, addr)
				return
			}
		}

		// Сетевой запрос выполняется без mutex.
		DNSAnswer, err := DNSManager.GetDNSFromHTTPMessage(
			&DNSRequest,
		)

		if err == nil {
			// NXDOMAIN и NOERROR/NODATA — корректные DNS-ответы.
			// Передаем их клиенту без подмены на SERVFAIL.
			DNSAnswer.Question = append(
				[]dns.Question(nil),
				DNSRequest.Question...,
			)
			DNSAnswer.Response = true

			// Кешируем только положительные ответы.
			// Отрицательные ответы не добавляем в IP-маршруты.
			positive := DNSAnswer.Rcode == dns.RcodeSuccess &&
				len(DNSAnswer.Answer) > 0

			if Config.Debug {
				fmt.Printf(
					"[DEBUG] DoH response: domain=%s, rcode=%s, answers=%d\n",
					domain,
					dns.RcodeToString[DNSAnswer.Rcode],
					len(DNSAnswer.Answer),
				)
			}

			if positive {
				if Config.EnableCache {
					if routeDomain {
						DNSManager.AddCache(DNSAnswer)
					} else if dohOnlyDomain {
						DNSManager.AddDoHOnlyCache(DNSAnswer)
					}
				}
				if routeDomain {
					DNSManager.AddToRoute(&DNSAnswer)
				}
			}

			DNSAnswer.Id = DNSRequest.Id
			answer, packErr := DNSAnswer.Pack()
			if packErr != nil {
				fmt.Println("Failed pack DoH DNS response:", packErr)
				return
			}
			if _, writeErr := DNSManager.UDPSock.WriteTo(answer, addr); writeErr != nil {
				fmt.Println("Failed send DoH DNS response:", writeErr)
			}
			return
		}

		if Config.Debug {
			fmt.Printf(
				"[DEBUG] DoH request failed: domain=%s, error=%v\n",
				domain, err,
			)
		}

		// Домены из маршрутизации и DoH-only никогда
		// не переключаются на обычные DNS-серверы
		// при отказе DoH. Возвращаем SERVFAIL.
		DNSFailure := new(dns.Msg)
		DNSFailure.SetRcode(
			&DNSRequest,
			dns.RcodeServerFailure,
		)

		buffer, packErr := DNSFailure.Pack()
		if packErr != nil {
			fmt.Println(
				"Failed pack DoH SERVFAIL response:",
				packErr,
			)
			return
		}

		if _, writeErr := DNSManager.UDPSock.WriteTo(
			buffer,
			addr,
		); writeErr != nil {
			fmt.Println(
				"Failed send DoH SERVFAIL response:",
				writeErr,
			)
		}

		return
	}

	// Обычные DNS-серверы: перебираем, пока не получим записи Answer.
	// NXDOMAIN/NODATA запоминаем и возвращаем только если все серверы
	// не дали положительного ответа.
	var lastNegative *dns.Msg
	for _, server := range DNSManager.ServerSnapshot() {
		protocol, address, parseErr := DNSManager.ParseDNSServer(server)
		if parseErr != nil {
			if Config.Debug {
				fmt.Printf("[DEBUG] Invalid DNS server %s: %v\n", server, parseErr)
			}
			continue
		}

		var DNSAnswer dns.Msg
		switch protocol {
		case "https":
			answer, getErr := DNSManager.GetDNSFromDoHServer(&DNSRequest, address)
			if getErr != nil {
				if Config.Debug {
					fmt.Printf("[DEBUG] Failed DoH %s, domain=%s: %v\n", server, domain, getErr)
				}
				continue
			}
			DNSAnswer = answer
		case "udp":
			DNSAnswer = DNSManager.GetDNSFromDNSServer(&DNSRequest, address)
		default:
			continue
		}

		if !DNSAnswer.Response {
			continue
		}
		if DNSAnswer.Rcode != dns.RcodeSuccess && DNSAnswer.Rcode != dns.RcodeNameError {
			if Config.Debug {
				fmt.Printf("[DEBUG] DNS server %s failed, domain=%s, rcode=%d\n", server, domain, DNSAnswer.Rcode)
			}
			continue
		}

		if Config.Debug {
			fmt.Printf("[DEBUG] DNS response from %s: domain=%s, rcode=%d, answers=%d\n", server, domain, DNSAnswer.Rcode, len(DNSAnswer.Answer))
		}
		if DNSAnswer.Rcode == dns.RcodeSuccess && len(DNSAnswer.Answer) > 0 {
			DNSAnswer.Id = DNSRequest.Id
			packet, packErr := DNSAnswer.Pack()
			if packErr != nil {
				fmt.Println("Failed pack DNS response:", packErr)
				return
			}
			if _, writeErr := DNSManager.UDPSock.WriteTo(packet, addr); writeErr != nil {
				fmt.Println("Failed send DNS response:", writeErr)
			}
			return
		}

		// Сохраняем первый отрицательный ответ, а перебор продолжаем.
		// Так не теряем NXDOMAIN/NODATA, если следующие серверы недоступны.
		if lastNegative == nil {
			lastNegative = DNSAnswer.Copy()
		}
	}

	if lastNegative != nil {
		lastNegative.Id = DNSRequest.Id
		packet, packErr := lastNegative.Pack()
		if packErr != nil {
			fmt.Println("Failed pack negative DNS response:", packErr)
			return
		}
		if _, writeErr := DNSManager.UDPSock.WriteTo(packet, addr); writeErr != nil {
			fmt.Println("Failed send negative DNS response:", writeErr)
		}
		return
	}

	// Не получили ни положительного, ни корректного отрицательного ответа.
	failure := new(dns.Msg)
	failure.SetRcode(&DNSRequest, dns.RcodeServerFailure)
	packet, packErr := failure.Pack()
	if packErr != nil {
		fmt.Println("Failed pack DNS SERVFAIL response:", packErr)
		return
	}
	if _, writeErr := DNSManager.UDPSock.WriteTo(packet, addr); writeErr != nil {
		fmt.Println("Failed send DNS SERVFAIL response:", writeErr)
	}

}

// ParseDNSServer поддерживает:
// 8.8.8.8
// 8.8.8.8:53
// udp://8.8.8.8
// udp://8.8.8.8:53
// https://dns.google
// https://dns.google/dns-query
func (DNSManager *SDNSManager) ParseDNSServer(
	server string,
) (string, string, error) {
	server = strings.TrimSpace(server)

	if server == "" {
		return "", "", fmt.Errorf("empty DNS server")
	}

	if strings.HasPrefix(
		strings.ToLower(server),
		"https://",
	) {
		u, err := url.Parse(server)
		if err != nil {
			return "", "", err
		}

		if u.Host == "" ||
			u.Hostname() == "" ||
			u.User != nil {
			return "", "", fmt.Errorf(
				"invalid DoH server: %s",
				server,
			)
		}

		if u.Path == "" || u.Path == "/" {
			u.Path = "/dns-query"
		}

		return "https", u.String(), nil
	}

	if strings.HasPrefix(
		strings.ToLower(server),
		"udp://",
	) {
		server = server[6:]
	}

	if strings.Contains(server, "://") {
		return "", "", fmt.Errorf(
			"unsupported DNS protocol: %s",
			server,
		)
	}

	if server == "" {
		return "", "", fmt.Errorf(
			"empty DNS server address",
		)
	}

	if _, _, err := net.SplitHostPort(server); err == nil {
		return "udp", server, nil
	}

	if net.ParseIP(server) != nil {
		return "udp", net.JoinHostPort(server, "53"), nil
	}

	if strings.Contains(server, ":") {
		return "", "", fmt.Errorf(
			"invalid DNS server address: %s",
			server,
		)
	}

	return "udp", net.JoinHostPort(server, "53"), nil
}

// GetDNSFromDoHServer отправляет исходный DNS-пакет
// через HTTPS с форматом application/dns-message.
func (DNSManager *SDNSManager) GetDNSFromDoHServer(
	DNSRequest *dns.Msg,
	DoHServer string,
) (dns.Msg, error) {
	requestBody, err := DNSRequest.Pack()
	if err != nil {
		return dns.Msg{}, fmt.Errorf(
			"failed to pack DNS request: %w",
			err,
		)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		DoHServer,
		bytes.NewReader(requestBody),
	)
	if err != nil {
		return dns.Msg{}, fmt.Errorf(
			"failed to create DoH request: %w",
			err,
		)
	}

	req.Header.Set(
		"Content-Type",
		"application/dns-message",
	)
	req.Header.Set(
		"Accept",
		"application/dns-message",
	)

	client := &http.Client{
		Timeout: time.Duration(Config.DNSTimeout) * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return dns.Msg{}, fmt.Errorf(
			"DoH request failed: %w",
			err,
		)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return dns.Msg{}, fmt.Errorf(
			"DoH server returned HTTP %d",
			resp.StatusCode,
		)
	}

	body, err := io.ReadAll(
		io.LimitReader(resp.Body, 65536),
	)
	if err != nil {
		return dns.Msg{}, fmt.Errorf(
			"failed to read DoH response: %w",
			err,
		)
	}

	var DNSAnswer dns.Msg

	if err := DNSAnswer.Unpack(body); err != nil {
		return dns.Msg{}, fmt.Errorf(
			"failed to unpack DoH response: %w",
			err,
		)
	}

	if !DNSAnswer.Response {
		return dns.Msg{}, fmt.Errorf(
			"DoH server did not return DNS response",
		)
	}

	if DNSAnswer.Id != DNSRequest.Id {
		return dns.Msg{}, fmt.Errorf(
			"DoH response ID mismatch",
		)
	}

	if len(DNSAnswer.Question) != len(DNSRequest.Question) {
		return dns.Msg{}, fmt.Errorf(
			"DoH response question count mismatch",
		)
	}

	for i := range DNSRequest.Question {
		requestQuestion := DNSRequest.Question[i]
		answerQuestion := DNSAnswer.Question[i]

		if !strings.EqualFold(
			requestQuestion.Name,
			answerQuestion.Name,
		) ||
			requestQuestion.Qtype != answerQuestion.Qtype ||
			requestQuestion.Qclass != answerQuestion.Qclass {
			return dns.Msg{}, fmt.Errorf(
				"DoH response question mismatch",
			)
		}
	}

	return DNSAnswer, nil
}

func (DNSManager *SDNSManager) GetDNSFromDNSServer(
	DNSRequest *dns.Msg,
	DNSServer string,
) dns.Msg {
	conn, errdial := net.Dial("udp", DNSServer)
	if errdial != nil {
		if Config.Debug {
			fmt.Printf(
				"[DEBUG] Failed LocalDNS %s with error %s\n",
				DNSManager.GetDomain(DNSRequest),
				errdial.Error(),
			)
		}
		return *DNSRequest
	}
	defer conn.Close()

	err := conn.SetDeadline(
		time.Now().Add(
			time.Duration(Config.DNSTimeout) * time.Second,
		),
	)
	if err != nil {
		fmt.Println("Failed to set deadline:", err)
		return dns.Msg{}
	}

	buf, err := DNSRequest.Pack()
	if err != nil {
		fmt.Printf(
			"Failed DNSRequest pack with error %s\n",
			err.Error(),
		)
		return *DNSRequest
	}

	_, errw := conn.Write(buf)
	if errw != nil {
		fmt.Printf(
			"Failed write to DNS with error: %s\n",
			errw.Error(),
		)
		return *DNSRequest
	}

	ReadBuf := make([]byte, 65535)
	n, err := conn.Read(ReadBuf)

	if n <= 0 || err != nil {
		if Config.Debug {
			fmt.Printf(
				"[DEBUG] Failed DNS (domain %s) with error: %v\n",
				DNSManager.GetDomain(DNSRequest),
				err,
			)
		}
		return *DNSRequest
	}

	DNSAnswer := dns.Msg{}

	errpack := DNSAnswer.Unpack(ReadBuf[:n])
	if errpack != nil {
		fmt.Printf(
			"Failed to parse DNS with error: %s\n",
			errpack.Error(),
		)
		return *DNSRequest
	}

	return DNSAnswer
}

func (DNSManager *SDNSManager) LoadDNSRegexList() {
	path := Config.WorkDir + "services.txt"
	entries := readRegexFile(path)

	DNSManager.mutex.Lock()
	DNSManager.DNSRegexList = entries
	DNSManager.mutex.Unlock()
}

func (DNSManager *SDNSManager) IsDomainMatch(
	domain string,
) bool {
	route, _ := DNSManager.domainMode(domain)
	return route
}

func (DNSManager *SDNSManager) GetDomain(
	DNSRecord *dns.Msg,
) string {
	if len(DNSRecord.Question) == 0 {
		fmt.Println("Ошибка: в DNS-запросе отсутствуют вопросы")
		return "invalid"
	}

	return strings.TrimSuffix(
		DNSRecord.Question[0].Name,
		".",
	)
}

// isCacheLocked выполняется только при удержании mutex.
// Кеш проверяется по домену и типу DNS-запроса,
// чтобы ответ для A не возвращался на запрос AAAA.
func (DNSManager *SDNSManager) isCacheLocked(
	domain string,
	DNSRequest *dns.Msg,
) (dns.Msg, bool) {
	for _, DNSRecord := range DNSManager.DNSList {
		DNSDomain := DNSManager.GetDomain(&DNSRecord)

		if !strings.EqualFold(DNSDomain, domain) {
			continue
		}

		if len(DNSRecord.Question) == 0 ||
			len(DNSRequest.Question) == 0 {
			continue
		}

		if DNSRecord.Question[0].Qtype !=
			DNSRequest.Question[0].Qtype ||
			DNSRecord.Question[0].Qclass !=
				DNSRequest.Question[0].Qclass {
			continue
		}

		return *DNSRecord.Copy(), true
	}

	return dns.Msg{}, false
}

func (DNSManager *SDNSManager) IsCache(
	domain string,
	DNSRequest *dns.Msg,
) (dns.Msg, bool) {
	DNSManager.mutex.Lock()
	defer DNSManager.mutex.Unlock()

	return DNSManager.isCacheLocked(
		domain,
		DNSRequest,
	)
}

func (DNSManager *SDNSManager) AddCache(
	DNSRecord dns.Msg,
) {
	DNSManager.mutex.Lock()
	defer DNSManager.mutex.Unlock()

	// Не допускаем накопления одинаковых записей
	// при одновременных запросах.
	if len(DNSRecord.Question) > 0 {
		domain := DNSManager.GetDomain(&DNSRecord)

		for i := range DNSManager.DNSList {
			existing := &DNSManager.DNSList[i]

			if len(existing.Question) == 0 {
				continue
			}

			if strings.EqualFold(
				DNSManager.GetDomain(existing),
				domain,
			) &&
				existing.Question[0].Qtype ==
					DNSRecord.Question[0].Qtype &&
				existing.Question[0].Qclass ==
					DNSRecord.Question[0].Qclass {

				DNSManager.DNSList[i] = *DNSRecord.Copy()
				return
			}
		}
	}

	DNSManager.DNSList = append(
		DNSManager.DNSList,
		*DNSRecord.Copy(),
	)
}

// DoH-only использует отдельный список.
// Основные IsCache/AddCache не изменяются.
func (DNSManager *SDNSManager) IsDoHOnlyCache(
	domain string,
	request *dns.Msg,
) (dns.Msg, bool) {
	DNSManager.mutex.Lock()
	defer DNSManager.mutex.Unlock()

	for _, record := range DNSManager.DNSOnlyList {
		if len(record.Question) == 0 ||
			len(request.Question) == 0 {
			continue
		}

		if strings.EqualFold(
			DNSManager.GetDomain(&record),
			domain,
		) &&
			record.Question[0].Qtype ==
				request.Question[0].Qtype &&
			record.Question[0].Qclass ==
				request.Question[0].Qclass {
			return *record.Copy(), true
		}
	}

	return dns.Msg{}, false
}

func (DNSManager *SDNSManager) AddDoHOnlyCache(
	record dns.Msg,
) {
	if len(record.Question) == 0 {
		return
	}

	DNSManager.mutex.Lock()
	defer DNSManager.mutex.Unlock()

	for i := range DNSManager.DNSOnlyList {
		current := &DNSManager.DNSOnlyList[i]

		if len(current.Question) != 0 &&
			strings.EqualFold(
				DNSManager.GetDomain(current),
				DNSManager.GetDomain(&record),
			) &&
			current.Question[0].Qtype ==
				record.Question[0].Qtype &&
			current.Question[0].Qclass ==
				record.Question[0].Qclass {

			DNSManager.DNSOnlyList[i] = *record.Copy()
			return
		}
	}

	DNSManager.DNSOnlyList = append(
		DNSManager.DNSOnlyList,
		*record.Copy(),
	)
}

// Второй кеш обновляется независимо от первого,
// с тем же интервалом DNSCacheRefresh.
func (DNSManager *SDNSManager) UpdateDoHOnlyCacheLoop() {
	for {
		time.Sleep(
			time.Duration(Config.DNSCacheRefresh) * time.Second,
		)
		DNSManager.UpdateDoHOnlyCache()
	}
}

// Обновляет только DoH-only записи без изменения маршрутов.
func (DNSManager *SDNSManager) UpdateDoHOnlyCache() {
	DNSManager.mutex.Lock()

	records := make([]dns.Msg, len(DNSManager.DNSOnlyList))
	for i := range DNSManager.DNSOnlyList {
		records[i] = *DNSManager.DNSOnlyList[i].Copy()
	}

	version := DNSManager.cacheVersion
	DNSManager.mutex.Unlock()

	for _, record := range records {
		if len(record.Question) == 0 {
			continue
		}

		domain := DNSManager.GetDomain(&record)
		route, only := DNSManager.domainMode(domain)

		if route || !only {
			continue
		}

		answer, err := DNSManager.GetDNSFromHTTPMessage(
			&record,
		)
		if err != nil || len(answer.Answer) == 0 {
			if err != nil {
				fmt.Printf(
					"Failed update DoH-only %s: %v\n",
					domain,
					err,
				)
			}
			continue
		}

		answer.Question = append(
			[]dns.Question(nil),
			record.Question...,
		)
		answer.Response = true

		DNSManager.mutex.Lock()

		if DNSManager.cacheVersion == version {
			for i := range DNSManager.DNSOnlyList {
				current := &DNSManager.DNSOnlyList[i]

				if len(current.Question) != 0 &&
					strings.EqualFold(
						DNSManager.GetDomain(current),
						domain,
					) &&
					current.Question[0].Qtype ==
						record.Question[0].Qtype &&
					current.Question[0].Qclass ==
						record.Question[0].Qclass {

					DNSManager.DNSOnlyList[i] = *answer.Copy()
					break
				}
			}
		}

		DNSManager.mutex.Unlock()
		time.Sleep(500 * time.Millisecond)
	}
}

func (DNSManager *SDNSManager) AddToRoute(
	DNSRecord *dns.Msg,
) {
	var IPList []string

	for i := range DNSRecord.Answer {
		if DNSRecord.Answer[i].Header().Rrtype == dns.TypeA {
			IPList = append(
				IPList,
				DNSRecord.Answer[i].(*dns.A).A.String(),
			)
		}
	}

	if len(IPList) > 0 {
		if Config.Debug {
			fmt.Printf(
				"[DEBUG] Add IP in routing list: %s\n",
				IPList,
			)
		}

		Route.AddToRoute(IPList)
	}
}

// RestoreCachedRoutesLoop проверяет наличие маршрутов для IP
// из основного DNS-кеша раз в минуту.
// Записи DoH-only не передаются в routemanager.
func (DNSManager *SDNSManager) RestoreCachedRoutesLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		DNSManager.mutex.Lock()

		records := make([]dns.Msg, len(DNSManager.DNSList))
		for i := range DNSManager.DNSList {
			records[i] = *DNSManager.DNSList[i].Copy()
		}

		DNSManager.mutex.Unlock()

		for _, record := range records {
			domain := DNSManager.GetDomain(&record)
			route, _ := DNSManager.domainMode(domain)

			if !route {
				continue
			}

			DNSManager.AddToRoute(&record)
		}
	}
}

// Обновление существующего основного кеша.
func (DNSManager *SDNSManager) UpdateCacheLoop() {
	for {
		time.Sleep(
			time.Duration(Config.DNSCacheRefresh) * time.Second,
		)

		DNSManager.mutex.Lock()

		records := make([]dns.Msg, len(DNSManager.DNSList))
		for i := range DNSManager.DNSList {
			records[i] = *DNSManager.DNSList[i].Copy()
		}

		version := DNSManager.cacheVersion
		DNSManager.mutex.Unlock()

		for _, DNSRecord := range records {
			domain := DNSManager.GetDomain(&DNSRecord)

			routeDomain, _ := DNSManager.domainMode(domain)
			if !routeDomain {
				continue
			}

			fmt.Printf(
				"Start update domian: %s\n",
				domain,
			)

			DNSAnswer, err := DNSManager.GetDNSFromHTTPMessage(
				&DNSRecord,
			)
			if err != nil {
				fmt.Printf(
					"Failed update %s with error: %s\n",
					domain,
					err.Error(),
				)
				continue
			}

			if len(DNSAnswer.Answer) == 0 {
				continue
			}

			DNSAnswer.Question = append(
				[]dns.Question(nil),
				DNSRecord.Question...,
			)
			DNSAnswer.Response = true

			DNSManager.mutex.Lock()
			updated := false

			if DNSManager.cacheVersion == version {
				for i := range DNSManager.DNSList {
					current := &DNSManager.DNSList[i]

					if len(current.Question) == 0 ||
						len(DNSRecord.Question) == 0 {
						continue
					}

					if strings.EqualFold(
						DNSManager.GetDomain(current),
						domain,
					) &&
						current.Question[0].Qtype ==
							DNSRecord.Question[0].Qtype &&
						current.Question[0].Qclass ==
							DNSRecord.Question[0].Qclass {

						DNSManager.DNSList[i] = *DNSAnswer.Copy()
						updated = true
						break
					}
				}
			}

			DNSManager.mutex.Unlock()

			if updated {
				route, _ := DNSManager.domainMode(domain)
				if route {
					DNSManager.AddToRoute(&DNSAnswer)
				}
			}

			time.Sleep(500 * time.Millisecond)
		}

		fmt.Println("Cache updated")
	}
}

// GetDNSFromHTTP оставлен для совместимости с прежними вызовами.
func (DNSManager *SDNSManager) GetDNSFromHTTP(
	domain string,
) (dns.Msg, error) {
	request := new(dns.Msg)
	request.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	return DNSManager.GetDNSFromHTTPMessage(request)
}

// Несколько основных DoH проверяются последовательно.
// Используется wire-format DoH POST.
func (DNSManager *SDNSManager) GetDNSFromHTTPMessage(
	request *dns.Msg,
) (dns.Msg, error) {
	servers := splitServers(Config.DoHServer)
	var lastErr error
	var lastNegative *dns.Msg

	for _, server := range servers {
		protocol, address, err := DNSManager.ParseDNSServer(server)
		if err != nil || protocol != "https" {
			lastErr = fmt.Errorf("primary DoH must use https: %s", server)
			continue
		}

		response, err := DNSManager.GetDNSFromDoHServer(request, address)
		if err != nil {
			lastErr = err
			if Config.Debug {
				fmt.Printf("[DEBUG] Primary DoH %s failed: %v\n", address, err)
			}
			continue
		}

		// Ответ с записями — успешный; прекращаем перебор.
		if response.Rcode == dns.RcodeSuccess && len(response.Answer) > 0 {
			return response, nil
		}

		// NXDOMAIN и NOERROR без Answer — не сетевые ошибки.
		// Но перебираем остальные DoH на случай, если они найдут записи.
		if response.Rcode == dns.RcodeNameError || response.Rcode == dns.RcodeSuccess {
			if lastNegative == nil {
				lastNegative = response.Copy()
			}
			continue
		}

		lastErr = fmt.Errorf("primary DoH %s returned rcode %s", address, dns.RcodeToString[response.Rcode])
	}

	// Все DoH проверены: возвращаем отрицательный ответ, если он был.
	if lastNegative != nil {
		return *lastNegative, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no primary DoH configured")
	}
	return dns.Msg{}, lastErr
}

func (DNSManager *SDNSManager) ResetCache(
	AdguardEnabled bool,
) (err error) {
	if AdguardEnabled {
		err := AdGuardHome.ResetCache()
		if err != nil {
			fmt.Println(
				"Failed reset Adguard DNS Cache:",
				err,
			)
			return fmt.Errorf(
				"Failed reset Adguard DNS Cache: %s",
				err.Error(),
			)
		}
	} else {
		cmd := exec.Command(
			"/etc/init.d/dnsmasq",
			"restart",
		)

		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Println(
				"Failed reset DNSMasq DNS Cache:",
				string(output),
			)
			return fmt.Errorf(
				"Failed reset DNSMasq DNS Cache: %s",
				string(output),
			)
		}
	}

	DNSManager.mutex.Lock()
	DNSManager.DNSList = []dns.Msg{}
	DNSManager.DNSOnlyList = []dns.Msg{}
	DNSManager.cacheVersion++
	DNSManager.mutex.Unlock()

	return nil
}
