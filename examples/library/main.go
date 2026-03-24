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
		Timeout:        3 * time.Second,
		DetectHomepage: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	if err := runPortExample(scanner); err != nil {
		log.Fatal(err)
	}

	//if err := runHomepageExample(scanner); err != nil {
	//	log.Fatal(err)
	//}
	//if err := runDirExample(scanner); err != nil {
	//	log.Fatal(err)
	//}
}

func runPortExample(scanner *assetprobe.Scanner) error {
	result, err := scanner.Scan(context.Background(), assetprobe.ScanRequest{
		Target:      "pbc.cntd.org.cn",
		PortSpec:    "1-65535",
		Protocol:    assetprobe.ProtocolTCP,
		Concurrency: 10000,
	})
	if err != nil {
		return err
	}

	toJSON, err := result.ToJSON(true)
	fmt.Println(string(toJSON))
	return nil
}

func runHomepageExample(scanner *assetprobe.Scanner) error {
	result, err := scanner.DetectHomepage(context.Background(), "https://pbc.cntd.org.cn:56997")
	if err != nil {
		return err
	}

	fmt.Println("== Homepage Example ==")
	out, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(out))
	return nil
}

func runDirExample(scanner *assetprobe.Scanner) error {
	result, err := scanner.ScanDirectories(context.Background(), "https://example.com", assetprobe.DirBruteOptions{
		Enable:      true,
		Level:       assetprobe.DirBruteSimple,
		MaxPaths:    20,
		Concurrency: 10,
	})
	if err != nil {
		return err
	}

	fmt.Println("== Dir Example ==")
	out, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(out))
	return nil
}
