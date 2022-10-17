package web

import (
	. "dnsrouting/adguardmanager"
	. "dnsrouting/configmanager"
	. "dnsrouting/dnsmanager"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/buger/jsonparser"
)

type SData struct {
	DNSServers    string
	DNSRegexList  string
	DNSHTTPServer string
	AdGuard       bool
	AdGuardUrl    string
	AdGuardSecret string
}

//go:embed favicon.ico
var FaviconIcon []byte

//go:embed *.html
var index embed.FS

func Start() {
	http.HandleFunc("/", HTTPHandler)
	http.HandleFunc("/favicon.ico", HTTPFaviconHandler)
	http.HandleFunc("/Save", HTTPSaveHandler)

	err := http.ListenAndServe(":4000", nil)
	if err != nil {
		fmt.Println("Fail start web with error:", err.Error())
		os.Exit(1)
	}
}

func HTTPFaviconHandler(w http.ResponseWriter, r *http.Request) {
	w.Write(FaviconIcon)
}

func HTTPSaveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Write([]byte("Method not allowed (only POST)"))
		return
	}

	defer r.Body.Close()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.Write([]byte(err.Error()))
		return
	}

	HasConfigChange := false
	jsonparser.ArrayEach(body, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		AdGuard, err := jsonparser.GetBoolean(value, "AdGuard")
		if err == nil {
			HasConfigChange = true
			Config.AdGuard = AdGuard
		}

		AdGuardUrl, err := jsonparser.GetString(value, "AdGuardUrl")
		if err == nil {
			HasConfigChange = true
			Config.AdGuardUrl = AdGuardUrl
		}

		AdGuardSecret, err := jsonparser.GetString(value, "AdGuardSecret")
		if err == nil {
			HasConfigChange = true
			Config.AdGuardSecret = base64.StdEncoding.EncodeToString([]byte(AdGuardSecret))
		}

		DoHServer, err := jsonparser.GetString(value, "DoHServer")
		if err == nil {
			HasConfigChange = true
			Config.DoHServer = DoHServer
		}

		DNSServers, err := jsonparser.GetString(value, "DNSServers")
		if err == nil {
			HasConfigChange = true
			Config.DNSServerList = strings.ReplaceAll(DNSServers, "\n", ";")
			DNSManager.InitDNSServers()
		}

		DNSRegexList, err := jsonparser.GetString(value, "DNSRegexList")
		if err == nil {
			err := os.WriteFile(fmt.Sprintf("%sservices.txt", Config.WorkDir), []byte(fmt.Sprintf("%s\n", DNSRegexList)), 0644)
			if err != nil {
				fmt.Println("Fail save DNS Regex List with error:", err.Error())
				w.Write([]byte(err.Error()))
				return
			}
			DNSManager.LoadDNSRegexList()

			if Config.AdGuard {
				err := AdGuardHome.ResetCache()
				if err != nil {
					fmt.Println("Fail reset DNS Cache:", err)
					w.Write([]byte(err.Error()))
					return
				}
			}
		}

		if HasConfigChange {
			Config.Save()
		}
	})

	w.Write([]byte("OK"))
}

func HTTPHandler(w http.ResponseWriter, r *http.Request) {
	template, err := template.ParseFS(index, "index.html")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	var data SData
	for _, DNSServer := range DNSManager.DNSServers {
		data.DNSServers = fmt.Sprintf("%s\n%s", data.DNSServers, DNSServer)
	}
	data.DNSRegexList = GetServiceList()
	data.DNSHTTPServer = Config.DoHServer
	data.AdGuard = Config.AdGuard
	data.AdGuardUrl = Config.AdGuardUrl
	decode, _ := base64.StdEncoding.DecodeString(Config.AdGuardSecret)
	data.AdGuardSecret = string(decode)

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
