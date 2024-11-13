package ntp

import (
	"log"
	"testing"
	"time"
)

func TestTime(t *testing.T) {
	timeServers := []string{
		"pool.ntp.org",
		"clock.isc.org",
		"time.windows.com",
		"time.nist.gov",
		"ntp.nsu.ru",
		"ntp.ntsc.ac.cn",
	}

	for _, server := range timeServers {
		remoteTime, err := Time(server)
		if err != nil {
			log.Fatal(err)
		}

		log.Println("remote time: " + remoteTime.UTC().Format(time.DateTime))
		log.Println("local time:  " + time.Now().UTC().Format(time.DateTime))
		log.Println("----------")
	}
}
