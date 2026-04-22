package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/yrighc/gomap/pkg/assetprobe"
	"github.com/yrighc/gomap/pkg/secprobe"
)

func main() {
	scanner, err := assetprobe.NewScanner(assetprobe.Options{
		PortConcurrency: 200,
		PortRateLimit:   3000,
		Timeout:         3 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}

	//if err := runPortExample(scanner); err != nil {
	//	log.Fatal(err)
	//}

	//if err := runBatchPortExample(scanner); err != nil {
	//	log.Fatal(err)
	//}

	if err := runHomepageExample(scanner); err != nil {
		log.Fatal(err)
	}

	//if err := runDetectHomepageWithOptions(scanner); err != nil {
	//	log.Fatal(err)
	//}

	//if err := runDirExample(scanner); err != nil {
	//	log.Fatal(err)
	//}

	//if err := runWeakExample(scanner); err != nil {
	//	log.Fatal(err)
	//}
}

func runPortExample(scanner *assetprobe.Scanner) error {
	result, err := scanner.Scan(context.Background(), assetprobe.ScanRequest{
		Target:   "42.194.159.250",
		PortSpec: "80",
		Protocol: assetprobe.ProtocolTCP,

		PortConcurrency: 5000,
		PortRateLimit:   7000,
	})
	if err != nil {
		return err
	}

	fmt.Println("== Port Example ==")
	toJSON, err := result.ToJSON(true)
	fmt.Println(string(toJSON))
	return nil
}

func runBatchPortExample(scanner *assetprobe.Scanner) error {
	result, err := scanner.ScanTargets(context.Background(), []string{
		"127.0.0.1",
		"example.com",
	}, assetprobe.ScanCommonOptions{
		PortSpec:        "80,443",
		Protocol:        assetprobe.ProtocolTCP,
		PortConcurrency: 100,
	})
	if err != nil {
		return err
	}

	fmt.Println("== Batch Port Example ==")
	out, _ := result.ToJSON(true)
	fmt.Println(string(out))
	return nil
}

func runHomepageExample(scanner *assetprobe.Scanner) error {
	result, err := scanner.DetectHomepage(context.Background(), "http://192.168.100.100:8080")
	if err != nil {
		return err
	}

	fmt.Println("== Homepage Example ==")
	out, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(out))
	return nil
}

func runDetectHomepageWithOptions(scanner *assetprobe.Scanner) error {
	result, err := scanner.DetectHomepageWithOptions(
		context.Background(),
		"http://pbc.cntd.org.cn:56997",
		assetprobe.HomepageOptions{
			IncludeHeaders: true,
			MaxBodyBytes:   0,
		})
	if err != nil {
		return nil
	}
	out, _ := result.ToJSON(true)

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
	out, _ := result.ToJSON(true)
	fmt.Println(string(out))
	return nil
}

func runWeakExample(scanner *assetprobe.Scanner) error {
	result, err := scanner.Scan(context.Background(), assetprobe.ScanRequest{
		Target:   "127.0.0.1",
		PortSpec: "21,22,3306,5432,6379",
		Protocol: assetprobe.ProtocolTCP,
	})
	if err != nil {
		return err
	}

	security := secprobe.Run(
		context.Background(),
		secprobe.BuildCandidates(result, secprobe.CredentialProbeOptions{
			EnableUnauthorized: true,
			EnableEnrichment:   true,
		}),
		secprobe.CredentialProbeOptions{
			EnableUnauthorized: true,
			EnableEnrichment:   true,
		},
	)
	out, _ := security.ToJSON(true)

	fmt.Println("== Weak Example ==")
	fmt.Println(string(out))
	return nil
}
