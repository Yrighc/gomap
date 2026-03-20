package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/yrighc/gomap/pkg/assetprobe"
)

func main() {
	scanner, err := assetprobe.NewScanner(assetprobe.Options{
		Concurrency:    300,
		Timeout:        2 * time.Second,
		DetectHomepage: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	result, err := scanner.Scan(context.Background(), assetprobe.ScanRequest{
		Target:   "scanme.nmap.org",
		PortSpec: "22,80,443,3389,1-5",
		Protocol: assetprobe.ProtocolTCP,
		DirBrute: &assetprobe.DirBruteOptions{
			Enable:   true,
			Level:    assetprobe.DirBruteSimple,
			MaxPaths: 100,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	out, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(out))
}
