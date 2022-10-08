package web

import (
	. "dnsrouting/configmanager"
	. "dnsrouting/dnsmanager"
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
}

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
	file, err := os.ReadFile("favicon.ico")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(file)
}

func HTTPSaveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	defer r.Body.Close()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fmt.Println(string(body))

	HasConfigChange := false
	jsonparser.ArrayEach(body, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
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
			err := os.WriteFile("services.txt", []byte(fmt.Sprintf("%s\n", DNSRegexList)), 0644)
			if err != nil {
				fmt.Println("Fail save DNS Regex List with error:", err.Error())
				w.Write([]byte("danger:" + err.Error()))
			}
			DNSManager.LoadDNSRegexList()
		}

		if HasConfigChange {
			Config.Save()
		}
	})
}

func HTTPHandler(w http.ResponseWriter, r *http.Request) {
	template, err := template.ParseFiles("index.html")
	if err != nil {
		http.Error(w, "500 internal error", 500)
		return
	}

	var data SData
	for _, DNSServer := range DNSManager.DNSServers {
		data.DNSServers = fmt.Sprintf("%s\n%s", data.DNSServers, DNSServer)
	}
	data.DNSRegexList = GetServiceList()
	data.DNSHTTPServer = Config.DoHServer

	err = template.Execute(w, data)
	if err != nil {
		http.Error(w, "500 internal error", 500)
		return
	}
}

func GetServiceList() string {
	content, err := os.ReadFile("services.txt")
	if err != nil {
		return ""
	}

	return string(content)
}
