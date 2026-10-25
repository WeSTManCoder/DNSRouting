package dnsmanager

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestParseDNSServer(t *testing.T) {
	cases := []struct {
		input    string
		protocol string
		address  string
	}{
		{
			"8.8.8.8",
			"udp",
			"8.8.8.8:53",
		},
		{
			"udp://8.8.8.8",
			"udp",
			"8.8.8.8:53",
		},
		{
			"udp://8.8.8.8:5353",
			"udp",
			"8.8.8.8:5353",
		},
		{
			"https://dns.google",
			"https",
			"https://dns.google/dns-query",
		},
		{
			"https://dns.google/dns-query",
			"https",
			"https://dns.google/dns-query",
		},
	}

	for _, c := range cases {
		p, a, err := DNSManager.ParseDNSServer(c.input)

		if err != nil ||
			p != c.protocol ||
			a != c.address {
			t.Errorf(
				"%s: %q %q %v",
				c.input,
				p,
				a,
				err,
			)
		}
	}
}

func TestRulePriority(t *testing.T) {
	m := &SDNSManager{
		DNSRegexList: []string{
			`(^|\.)route\.example$`,
		},
		DNSOnlyRegexList: []string{
			`(^|\.)only\.example$`,
			`(^|\.)route\.example$`,
		},
	}

	tests := []struct {
		domain string
		route  bool
		only   bool
	}{
		{"route.example", true, false},
		{"sub.route.example", true, false},
		{"only.example", false, true},
		{"other.example", false, false},
	}

	for _, tc := range tests {
		route, only := m.domainMode(tc.domain)

		if route != tc.route || only != tc.only {
			t.Errorf(
				"%s route=%v only=%v",
				tc.domain,
				route,
				only,
			)
		}
	}
}

func TestServerOrder(t *testing.T) {
	servers := splitServers(
		"https://dns.google;\n8.8.8.8\nudp://1.1.1.1:53",
	)

	expected := "https://dns.google|8.8.8.8|udp://1.1.1.1:53"

	if strings.Join(servers, "|") != expected {
		t.Fatal(servers)
	}
}

func TestDoHOnlyCacheSeparateFromRouteCache(t *testing.T) {
	m := &SDNSManager{}

	request := new(dns.Msg)
	request.SetQuestion(
		"only.example.",
		dns.TypeA,
	)

	answer := new(dns.Msg)
	answer.SetReply(request)

	answer.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "only.example.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP("203.0.113.5").To4(),
		},
	}

	// Записываем ответ исключительно в DoH-only кеш.
	m.AddDoHOnlyCache(*answer)

	// Основной кеш должен оставаться пустым.
	if len(m.DNSList) != 0 ||
		len(m.DNSOnlyList) != 1 {
		t.Fatal(
			"DoH-only cache must be separate from routing cache",
		)
	}

	// Проверяем чтение записи из DoH-only кеша.
	got, ok := m.IsDoHOnlyCache(
		"only.example",
		request,
	)

	if !ok || len(got.Answer) != 1 {
		t.Fatal("DoH-only cache miss")
	}

	// Проверяем, что запись не появилась в основном кеше.
	if _, found := m.IsCache(
		"only.example",
		request,
	); found {
		t.Fatal(
			"DoH-only record leaked into routing cache",
		)
	}

	// A-запись не должна возвращаться на запрос AAAA.
	requestAAAA := new(dns.Msg)
	requestAAAA.SetQuestion(
		"only.example.",
		dns.TypeAAAA,
	)

	if _, found := m.IsDoHOnlyCache(
		"only.example",
		requestAAAA,
	); found {
		t.Fatal(
			"A record incorrectly served for AAAA",
		)
	}

	// Повторная запись того же домена не должна
	// создавать дубликат в кеше.
	m.AddDoHOnlyCache(*answer)

	if len(m.DNSOnlyList) != 1 {
		t.Fatal(
			"Duplicate DoH-only cache entry",
		)
	}
}
