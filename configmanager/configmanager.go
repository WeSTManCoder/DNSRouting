package configmanager

import (
	"fmt"
	"os"
	"strconv"

	"github.com/go-ini/ini"
)

type SConfig struct {
	//Порт сервиса DNSRouting
	Port int
	//Список DNS Over HTTPS
	DoHServer string
	//Список DNS серверов для резолва
	DNSServerList string
	//DNS таймаут
	DNSTimeout int
	//Время обновления DNS кеша
	DNSCacheRefresh int

	//Есть ли adguard?
	AdGuard bool

	//IP адрес ADGuard
	AdGuardUrl string

	//Секретный код Adguard
	AdGuardSecret string

	VPNInterface string

	conf *ini.File

	WorkDir string

	EnableCache bool

	Debug bool
}

var Config SConfig

func (config *SConfig) Init(path string) {
	config.WorkDir = path
	conf, err := ini.Load(fmt.Sprintf("%ssettings.ini", config.WorkDir))
	if err != nil {
		fmt.Printf("Fail load %ssettings.ini, err: %s\n", config.WorkDir, err.Error())
		os.Exit(1)
	}

	config.conf = conf

	err = config.conf.MapTo(&config)
	if err != nil {
		fmt.Println("Fail MapTo:", err.Error())
		os.Exit(1)
	}

	fmt.Printf("%+v\n", config)
}

func (config *SConfig) Save() {
	config.SetConfKey("Port", strconv.Itoa(Config.Port))
	config.SetConfKey("DoHServer", config.DoHServer)
	config.SetConfKey("DNSServerList", config.DNSServerList)
	config.SetConfKey("DNSTimeout", strconv.Itoa(config.DNSTimeout))
	config.SetConfKey("DNSCacheRefresh", strconv.Itoa(config.DNSCacheRefresh))
	config.SetConfKey("AdGuard", strconv.FormatBool(config.AdGuard))
	config.SetConfKey("AdGuardUrl", config.AdGuardUrl)
	config.SetConfKey("AdGuardSecret", config.AdGuardSecret)
	config.SetConfKey("VPNInterface", config.VPNInterface)
	config.SetConfKey("EnableCache", strconv.FormatBool(config.EnableCache))
	config.SetConfKey("Debug", strconv.FormatBool(config.EnableCache))

	err := config.conf.SaveTo(fmt.Sprintf("%ssettings.ini", config.WorkDir))
	if err != nil {
		fmt.Println("Fail save ini:", err.Error())
	}
}

func (config *SConfig) SetConfKey(key string, value string) {
	conf, err := config.conf.GetSection("")
	if err != nil {
		fmt.Println(err)
		return
	}

	k, err := conf.GetKey(key)
	if err != nil {
		fmt.Println(err)
		return
	}
	k.SetValue(value)
}
