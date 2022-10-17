package configmanager

import (
	"fmt"
	"os"

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

	conf *ini.File

	WorkDir string
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
	conf, err := config.conf.GetSection("")
	if err != nil {
		fmt.Println(err)
		return
	}

	k, err := conf.GetKey("DoHServer")
	if err != nil {
		fmt.Println(err)
		return
	}
	k.SetValue(config.DoHServer)

	k, err = conf.GetKey("DNSServerList")
	if err != nil {
		fmt.Println(err)
		return
	}
	k.SetValue(config.DNSServerList)

	k, err = conf.GetKey("AdGuardUrl")
	if err != nil {
		fmt.Println(err)
		return
	}
	k.SetValue(Config.AdGuardUrl)

	k, err = conf.GetKey("AdGuardSecret")
	if err != nil {
		fmt.Println(err)
		return
	}
	k.SetValue(Config.AdGuardSecret)

	k, err = conf.GetKey("AdGuard")
	if err != nil {
		fmt.Println(err)
		return
	}
	var AdGuard string
	if Config.AdGuard {
		AdGuard = "true"
	} else {
		AdGuard = "false"
	}
	k.SetValue(AdGuard)

	err = config.conf.SaveTo(fmt.Sprintf("%ssettings.ini", config.WorkDir))
	if err != nil {
		fmt.Println("Fail save ini:", err.Error())
	}
}
