package adguardmanager

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	. "dnsrouting/configmanager"

	"github.com/buger/jsonparser"
)

type SADGaurdHome struct {
}

var AdGuardHome SADGaurdHome

func (adguard *SADGaurdHome) ResetCache() error {
	CacheSize, err := adguard.GetCacheSize()
	if err != nil {
		return err
	}

	err = adguard.SetCacheSize(0)
	if err != nil {
		return err
	}

	err = adguard.SetCacheSize(CacheSize)
	if err != nil {
		return err
	}

	fmt.Println("AdGuardHome cache has been reseted")
	return nil
}

func (adguard *SADGaurdHome) SetCacheSize(size int64) error {
	buffer := strings.NewReader(fmt.Sprintf(`{"cache_size":%d}`, size))
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	request, err := http.NewRequest("POST", fmt.Sprintf("%s/control/dns_config", Config.AdGuardUrl), buffer)
	if err != nil {
		return err
	}

	request.Header.Add("Authorization", fmt.Sprintf("Basic %s", Config.AdGuardSecret))
	response, err := client.Do(request)
	if err != nil {
		return err
	}

	if response.StatusCode != 200 {
		return fmt.Errorf("status code: %d", response.StatusCode)
	}

	return nil
}

func (adguard *SADGaurdHome) GetCacheSize() (int64, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	request, err := http.NewRequest("GET", fmt.Sprintf("%s/control/dns_info", Config.AdGuardUrl), nil)
	if err != nil {
		return -1, err
	}

	request.Header.Add("Authorization", fmt.Sprintf("Basic %s", Config.AdGuardSecret))
	response, err := client.Do(request)
	if err != nil {
		return -1, err
	}

	defer response.Body.Close()

	Body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return -1, err
	}

	cachesize, err := jsonparser.GetInt(Body, "cache_size")
	if err != nil {
		return -1, err
	}

	return cachesize, nil
}
