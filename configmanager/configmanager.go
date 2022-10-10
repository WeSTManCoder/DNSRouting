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
	conf, _ := config.conf.GetSection("")

	k, _ := conf.GetKey("DoHServer")
	k.SetValue(config.DoHServer)
	k, _ = conf.GetKey("DNSServerList")
	k.SetValue(config.DNSServerList)

	err := config.conf.SaveTo(fmt.Sprintf("%ssettings.ini", config.WorkDir))
	if err != nil {
		fmt.Println("Fail save ini:", err.Error())
	}
}
