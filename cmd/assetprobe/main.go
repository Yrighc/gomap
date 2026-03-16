package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"gomap/pkg/assetprobe"
)

func main() {
	target := flag.String("target", "", "扫描目标 IP 或域名")
	ports := flag.String("ports", "80,443", "端口表达式，例如 80,443,1-1024")
	proto := flag.String("proto", "tcp", "扫描协议: tcp|udp")
	rate := flag.Int("rate", 200, "并发数")
	timeout := flag.Int("timeout", 2, "超时秒数")
	homepage := flag.Bool("homepage", true, "是否进行首页识别")
	dirBrute := flag.Bool("dirbrute", false, "是否启用目录爆破（依赖 app 字典）")
	dictLevel := flag.String("dict", "simple", "目录爆破字典级别: simple|normal|diff")
	dictFile := flag.String("dict-file", "", "自定义目录爆破字典文件路径")
	dictMax := flag.Int("dict-max", 0, "目录爆破最多加载路径条数，0 表示不限制")
	dictConcurrency := flag.Int("dict-concurrency", 50, "目录爆破并发数")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "target 不能为空，例如: -target example.com")
		os.Exit(1)
	}

	scanner, err := assetprobe.NewScanner(assetprobe.Options{
		Concurrency:    *rate,
		Timeout:        time.Duration(*timeout) * time.Second,
		DetectHomepage: *homepage,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	protocol := assetprobe.ProtocolTCP
	if *proto == "udp" {
		protocol = assetprobe.ProtocolUDP
	}

	res, err := scanner.Scan(context.Background(), assetprobe.ScanRequest{
		Target:   *target,
		PortSpec: *ports,
		Protocol: protocol,
		DirBrute: &assetprobe.DirBruteOptions{
			Enable:         *dirBrute,
			Level:          assetprobe.DirBruteLevel(*dictLevel),
			CustomDictFile: *dictFile,
			MaxPaths:       *dictMax,
			Concurrency:    *dictConcurrency,
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	output, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(output))
}
