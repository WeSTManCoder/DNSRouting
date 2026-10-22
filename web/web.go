package web

import (
	. "dnsrouting/configmanager"
	. "dnsrouting/dnsmanager"
	"dnsrouting/updater"
	. "dnsrouting/version"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type SData struct {
	DNSServers       string
	DNSRegexList     string
	DNSOnlyRegexList string
	DNSHTTPServer    string
	AdGuard          bool
	AdGuardUrl       string
	AdGuardSecret    string
	Port             string
	DNSTimeout       string
	DNSCacheRefresh  string
	VPNInterface     string
	Version          string
	Debug            bool
	AutoUpdate       bool
	UpdateServer     string
}

//go:embed favicon.ico
var FaviconIcon []byte

//go:embed jquery-3.6.1.min.js
var JQuery []byte

//go:embed bootstrap-5.0.2.min.css
var Bootstrap []byte

//go:embed *.html
var index embed.FS

func Start() {
	http.HandleFunc("/", HTTPHandler)
	http.HandleFunc("/favicon.ico", HTTPFaviconHandler)
	http.HandleFunc("/Save", HTTPSaveHandler)
	http.HandleFunc("/api/updates/check", HTTPUpdateCheck)
	http.HandleFunc("/api/updates/install", HTTPUpdateInstall)

	err := http.ListenAndServe(":4000", nil)
	if err != nil {
		fmt.Println("Fail start web with error:", err.Error())
		os.Exit(1)
	}
}

func HTTPFaviconHandler(w http.ResponseWriter, r *http.Request) {
	w.Write(FaviconIcon)
}

var webSaveMutex sync.Mutex

func HTTPSaveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var updates []map[string]json.RawMessage
	err := json.NewDecoder(io.LimitReader(r.Body, 1024*1024)).Decode(&updates)
	if err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Предварительная проверка исключает частичное изменение настроек при ошибке формата.
	for _, item := range updates {
		for key, raw := range item {
			switch key {
			case "Port", "DNSTimeout", "DNSCacheRefresh":
				var v string
				if err := json.Unmarshal(raw, &v); err != nil {
					http.Error(w, key+": expected string", 400)
					return
				}
				n, err := strconv.Atoi(v)
				if err != nil || n < 1 || (key == "Port" && n > 65535) {
					http.Error(w, "Invalid "+key, 400)
					return
				}
			case "DoHServer", "DNSServers":
				var v string
				if err := json.Unmarshal(raw, &v); err != nil {
					http.Error(w, "Invalid "+key, 400)
					return
				}
				servers := strings.FieldsFunc(v, func(r rune) bool { return r == ';' || r == '\n' || r == '\r' })
				if key == "DoHServer" && len(servers) == 0 {
					http.Error(w, "At least one DoH server is required", 400)
					return
				}
				for _, server := range servers {
					protocol, _, err := DNSManager.ParseDNSServer(strings.TrimSpace(server))
					if err != nil || (key == "DoHServer" && protocol != "https") {
						http.Error(w, "Invalid server: "+server, 400)
						return
					}
				}
			case "UpdateServer":
				var v string
				if err := json.Unmarshal(raw, &v); err != nil || updater.ValidateEndpoint(v) != nil {
					http.Error(w, "Invalid update server URL (HTTPS required)", 400)
					return
				}
			case "DNSRegexList", "DNSOnlyRegexList":
				var v string
				if err := json.Unmarshal(raw, &v); err != nil {
					http.Error(w, "Invalid "+key, 400)
					return
				}
				for _, line := range strings.Split(v, "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
						continue
					}
					if _, err := regexp.Compile(line); err != nil {
						http.Error(w, "Invalid regex: "+line+": "+err.Error(), 400)
						return
					}
				}
			}
		}
	}

	webSaveMutex.Lock()
	defer webSaveMutex.Unlock()
	configChanged := false
	resetCache := false
	for _, item := range updates {
		for key, raw := range item {
			switch key {
			case "Port":
				var v string
				_ = json.Unmarshal(raw, &v)
				Config.Port, _ = strconv.Atoi(v)
				configChanged = true
			case "DNSTimeout":
				var v string
				_ = json.Unmarshal(raw, &v)
				Config.DNSTimeout, _ = strconv.Atoi(v)
				configChanged = true
			case "DNSCacheRefresh":
				var v string
				_ = json.Unmarshal(raw, &v)
				Config.DNSCacheRefresh, _ = strconv.Atoi(v)
				configChanged = true
			case "AdGuard":
				var v bool
				if json.Unmarshal(raw, &v) == nil {
					Config.AdGuard = v
					configChanged = true
				}
			case "AdGuardUrl":
				var v string
				if json.Unmarshal(raw, &v) == nil {
					Config.AdGuardUrl = v
					configChanged = true
				}
			case "AdGuardSecret":
				var v string
				if json.Unmarshal(raw, &v) == nil {
					Config.AdGuardSecret = base64.StdEncoding.EncodeToString([]byte(v))
					configChanged = true
				}
			case "DoHServer":
				var v string
				_ = json.Unmarshal(raw, &v)
				Config.DoHServer = strings.Join(strings.FieldsFunc(v, func(r rune) bool { return r == ';' || r == '\n' || r == '\r' }), ";")
				configChanged = true
				resetCache = true
			case "DNSServers":
				var v string
				_ = json.Unmarshal(raw, &v)
				Config.DNSServerList = strings.Join(strings.FieldsFunc(v, func(r rune) bool { return r == ';' || r == '\n' || r == '\r' }), ";")
				DNSManager.InitDNSServers()
				configChanged = true
			case "VPNInterface":
				var v string
				if json.Unmarshal(raw, &v) == nil {
					Config.VPNInterface = v
					configChanged = true
				}
			case "UpdateServer":
				var v string
				if json.Unmarshal(raw, &v) == nil {
					Config.UpdateServer = strings.TrimSpace(v)
					configChanged = true
				}
			case "AutoUpdate":
				var v bool
				if json.Unmarshal(raw, &v) == nil {
					Config.AutoUpdate = v
					configChanged = true
				}
			case "Debug":
				var v bool
				if json.Unmarshal(raw, &v) == nil {
					Config.Debug = v
					configChanged = true
				}
			case "DNSRegexList":
				var v string
				_ = json.Unmarshal(raw, &v)
				if err := os.WriteFile(Config.WorkDir+"services.txt", []byte(v+"\n"), 0644); err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				DNSManager.LoadDNSRegexList()
				resetCache = true
			case "DNSOnlyRegexList":
				var v string
				_ = json.Unmarshal(raw, &v)
				if err := os.WriteFile(Config.WorkDir+"doh-only.txt", []byte(v+"\n"), 0644); err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				DNSManager.LoadDNSOnlyRegexList()
				resetCache = true
			}
		}
	}
	if configChanged {
		Config.Save()
	}
	if resetCache {
		if err := DNSManager.ResetCache(Config.AdGuard); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("OK"))
}

func HTTPHandler(w http.ResponseWriter, r *http.Request) {
	request := r.RequestURI

	if request == "/jquery-3.6.1.min.js" {
		w.Write(JQuery)
		return
	}

	if request == "/bootstrap-5.0.2.min.css" {
		w.Write(Bootstrap)
		return
	}

	template, err := template.ParseFS(index, "index.html")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	var data SData
	for _, DNSServer := range DNSManager.ServerSnapshot() {
		data.DNSServers = fmt.Sprintf("%s\n%s", data.DNSServers, DNSServer)
	}

	data.Port = strconv.Itoa(Config.Port)
	data.DNSHTTPServer = Config.DoHServer
	data.DNSRegexList = GetServiceList()
	data.DNSOnlyRegexList = GetDNSOnlyList()
	data.DNSTimeout = strconv.Itoa(Config.DNSTimeout)
	data.DNSCacheRefresh = strconv.Itoa(Config.DNSCacheRefresh)
	data.AdGuard = Config.AdGuard
	data.AdGuardUrl = Config.AdGuardUrl
	decode, _ := base64.StdEncoding.DecodeString(Config.AdGuardSecret)
	data.AdGuardSecret = string(decode)
	data.VPNInterface = Config.VPNInterface
	data.Version = GetVersion()
	data.Debug = Config.Debug
	data.AutoUpdate = Config.AutoUpdate
	data.UpdateServer = Config.UpdateServer

	err = template.Execute(w, data)
	if err != nil {
		http.Error(w, "500 internal error", 500)
		return
	}
}

func GetServiceList() string {
	content, err := os.ReadFile(fmt.Sprintf("%sservices.txt", Config.WorkDir))
	if err != nil {
		return ""
	}

	return string(content)
}

func GetDNSOnlyList() string {
	content, err := os.ReadFile(Config.WorkDir + "doh-only.txt")
	if err != nil {
		return ""
	}
	return string(content)
}

// Update endpoints never accept arbitrary URLs, paths, or executables from the browser.
func HTTPUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	result, err := updater.Check(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	_ = json.NewEncoder(w).Encode(result)
}

func HTTPUpdateInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if r.Header.Get("Origin") != "" {
		origin := r.Header.Get("Origin")
		expected := "http://" + r.Host
		if r.TLS != nil {
			expected = "https://" + r.Host
		}
		if origin != expected {
			http.Error(w, "Invalid origin", 403)
			return
		}
	}
	result, err := updater.Install(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(result)
}
