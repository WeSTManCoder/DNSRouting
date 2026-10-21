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
	for _, server := range strings.FieldsFunc(value, func(r rune) bool { return r == ';' || r == '\n' || r == '\r' }) {
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
		if len(line) <= 2 || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
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

		// Проверяем кеш.
		// Mutex используется только для доступа к DNSList.
		if Config.EnableCache && routeDomain {
			DNSAnswer, HasCache := DNSManager.IsCache(
				domain,
				&DNSRequest,
			)

			if HasCache {
				if Config.Debug {
					fmt.Printf(
						"[DEBUG] Domain %s is in cache\n",
						domain,
					)
				}

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

		// Сетевой запрос выполняется БЕЗ mutex.
		// Другие запросы могут обрабатываться параллельно.
		DNSAnswer, err := DNSManager.GetDNSFromHTTPMessage(&DNSRequest)

		if err == nil && len(DNSAnswer.Answer) > 0 {
			if Config.Debug {
				fmt.Printf(
					"[DEBUG] YES answers from %s (%d), domain: %s\n",
					Config.DoHServer,
					len(DNSAnswer.Answer),
					domain,
				)
			}

			// Приводим вопрос к исходному запросу.
			// Это позволяет корректно возвращать ответ клиенту
			// и сохранять его в кеше с нужным типом.
			DNSAnswer.Question = append(
				[]dns.Question(nil),
				DNSRequest.Question...,
			)
			DNSAnswer.Response = true

			if Config.EnableCache && routeDomain {
				DNSManager.AddCache(DNSAnswer)
			}

			if routeDomain {
				DNSManager.AddToRoute(&DNSAnswer)
			}
			DNSAnswer.Id = DNSRequest.Id

			answer, err := DNSAnswer.Pack()
			if err != nil {
				fmt.Println(
					"Failed pack DoH DNS response:",
					err,
				)
				return
			}

			DNSManager.UDPSock.WriteTo(answer, addr)
			return
		} else if err != nil && Config.Debug {
			fmt.Printf(
				"[DEBUG] No answers from %s, domain: %s, error: %s\n",
				Config.DoHServer,
				domain,
				err.Error(),
			)
		}
	}

	// Обычный список DNS-серверов.
	// Порядок перебора полностью сохраняется.
	var DNSAnswer dns.Msg

	for _, server := range DNSManager.ServerSnapshot() {
		protocol, address, err := DNSManager.ParseDNSServer(
			server,
		)

		if err != nil {
			if Config.Debug {
				fmt.Printf(
					"[DEBUG] Invalid DNS server %s: %s\n",
					server,
					err.Error(),
				)
			}
			continue
		}

		switch protocol {
		case "https":
			answer, err := DNSManager.GetDNSFromDoHServer(
				&DNSRequest,
				address,
			)

			if err != nil {
				if Config.Debug {
					fmt.Printf(
						"[DEBUG] Failed DoH %s, domain: %s, error: %s\n",
						server,
						domain,
						err.Error(),
					)
				}
				continue
			}

			DNSAnswer = answer

		case "udp":
			DNSAnswer = DNSManager.GetDNSFromDNSServer(
				&DNSRequest,
				address,
			)
		}

		if len(DNSAnswer.Answer) > 0 {
			if Config.Debug {
				fmt.Printf(
					"[DEBUG] YES answers from %s (%d), domain: %s\n",
					server,
					len(DNSAnswer.Answer),
					domain,
				)
			}
			break
		} else if Config.Debug {
			fmt.Printf(
				"[DEBUG] No answers from %s, domain: %s\n",
				server,
				domain,
			)
		}
	}

	answer, err := DNSAnswer.Pack()
	if err != nil {
		fmt.Println(
			"Fail pack DNSAnswer with error:",
			err.Error(),
		)
		return
	}

	_, err = DNSManager.UDPSock.WriteTo(answer, addr)
	if err != nil {
		fmt.Println(
			"Fail to send DNS response to client:",
			err.Error(),
		)
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

	if strings.HasPrefix(strings.ToLower(server), "https://") {
		u, err := url.Parse(server)
		if err != nil {
			return "", "", err
		}

		if u.Host == "" || u.Hostname() == "" || u.User != nil {
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

	if strings.HasPrefix(strings.ToLower(server), "udp://") {
		server = server[6:]
	}

	if strings.Contains(server, "://") {
		return "", "", fmt.Errorf(
			"unsupported DNS protocol: %s",
			server,
		)
	}

	if server == "" {
		return "", "", fmt.Errorf("empty DNS server address")
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
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

func (DNSManager *SDNSManager) IsDomainMatch(domain string) bool {
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
//
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

	return DNSManager.isCacheLocked(domain, DNSRequest)
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

// RestoreCachedRoutesLoop проверяет наличие маршрутов для IP из DNS-кеша.
// В отличие от обновления DNS-кеша, эта проверка выполняется раз в минуту:
// маршруты восстанавливаются даже без повторного DNS-запроса от клиента.
// Записи DoH-only никогда не передаются в routemanager.
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

func (DNSManager *SDNSManager) UpdateCacheLoop() {
	for {
		time.Sleep(
			time.Duration(Config.DNSCacheRefresh) * time.Second,
		)

		// Делаем копию кеша и запоминаем версию.
		// Во время сетевых запросов mutex свободен.
		DNSManager.mutex.Lock()

		records := make([]dns.Msg, len(DNSManager.DNSList))
		for i := range DNSManager.DNSList {
			records[i] = *DNSManager.DNSList[i].Copy()
		}

		version := DNSManager.cacheVersion

		DNSManager.mutex.Unlock()

		for _, DNSRecord := range records {
			domain := DNSManager.GetDomain(&DNSRecord)

			// В кеше остаются только маршрутизируемые записи.
			// Если правило перенесено в DoH-only, не обновляем его
			// и не используем для добавления маршрутов.
			routeDomain, _ := DNSManager.domainMode(domain)
			if !routeDomain {
				continue
			}

			fmt.Printf(
				"Start update domian: %s\n",
				domain,
			)

			DNSAnswer, err := DNSManager.GetDNSFromHTTPMessage(&DNSRecord)
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

			// Сохраняем исходный вопрос.
			DNSAnswer.Question = append(
				[]dns.Question(nil),
				DNSRecord.Question...,
			)
			DNSAnswer.Response = true

			// Проверяем, что кеш не сбрасывался
			// за время сетевого запроса.
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

						DNSManager.DNSList[i] =
							*DNSAnswer.Copy()
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
func (DNSManager *SDNSManager) GetDNSFromHTTP(domain string) (dns.Msg, error) {
	request := new(dns.Msg)
	request.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	return DNSManager.GetDNSFromHTTPMessage(request)
}

// Несколько основных DoH проверяются последовательно в заданном порядке.
// Используется wire-format DoH POST, поэтому сохраняется Qtype исходного запроса.
func (DNSManager *SDNSManager) GetDNSFromHTTPMessage(request *dns.Msg) (dns.Msg, error) {
	servers := splitServers(Config.DoHServer)
	var lastErr error
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
		if len(response.Answer) > 0 {
			return response, nil
		}
		lastErr = fmt.Errorf("primary DoH %s returned no answers", address)
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
	DNSManager.cacheVersion++
	DNSManager.mutex.Unlock()

	return nil
}
