package dnsmanager

import (
	"strings"
	"testing"
)

func TestParseDNSServer(t *testing.T) {
	cases := []struct{ input, protocol, address string }{
		{"8.8.8.8", "udp", "8.8.8.8:53"},
		{"udp://8.8.8.8", "udp", "8.8.8.8:53"},
		{"udp://8.8.8.8:5353", "udp", "8.8.8.8:5353"},
		{"https://dns.google", "https", "https://dns.google/dns-query"},
		{"https://dns.google/dns-query", "https", "https://dns.google/dns-query"},
	}
	for _, c := range cases {
		p, a, err := DNSManager.ParseDNSServer(c.input)
		if err != nil || p != c.protocol || a != c.address {
			t.Errorf("%s: %q %q %v", c.input, p, a, err)
		}
	}
}

func TestRulePriority(t *testing.T) {
	m := &SDNSManager{
		DNSRegexList:     []string{`(^|\.)route\.example$`},
		DNSOnlyRegexList: []string{`(^|\.)only\.example$`, `(^|\.)route\.example$`},
	}
	tests := []struct {
		domain      string
		route, only bool
	}{
		{"route.example", true, false},
		{"sub.route.example", true, false},
		{"only.example", false, true},
		{"other.example", false, false},
	}
	for _, tc := range tests {
		route, only := m.domainMode(tc.domain)
		if route != tc.route || only != tc.only {
			t.Errorf("%s route=%v only=%v", tc.domain, route, only)
		}
	}
}

func TestServerOrder(t *testing.T) {
	servers := splitServers("https://dns.google;\n8.8.8.8\nudp://1.1.1.1:53")
	if strings.Join(servers, "|") != "https://dns.google|8.8.8.8|udp://1.1.1.1:53" {
		t.Fatal(servers)
	}
}
