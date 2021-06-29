package main

import (
	"log"
	"net/http"

	"github.com/mberhault/go-sct"
)

func main() {
	url := "https://www.baidu.com"
	// Known to return SCTs in TLS extensions.
	// url := "https://ritter.vg"

	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("get failed for %s: %v", url, err)
	}

	err = sct.CheckConnectionState(resp.TLS)
	if err != nil {
		log.Fatalf("failed SCT check: %v", err)
	}

	log.Printf("OK")
}
