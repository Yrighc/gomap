package service

// 解析 gomap-services 文件，存储端口对应的服务信息
import (
	"bufio"
	"fmt"
	"github.com/yrighc/gomap/config/common"
	"github.com/yrighc/gomap/config/logger"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

var mu sync.Mutex

func ServiceStorage() {
	if err := ServiceStorageFromFile(""); err != nil {
		logger.Info("Error initializing service storage:", err)
	}
}

func ServiceStorageFromFile(servicesPath string) error {
	path := servicesPath
	if path == "" {
		path = firstExistingPath(
			"./config/gomap-services",
			"./app/gomap-services",
		)
	}
	if path == "" {
		return os.ErrNotExist
	}

	// 打开 nmap-services 文件
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// 创建一个 map，用来存储端口号 -> 协议和服务名

	// 读取文件每一行
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// 忽略空行和注释
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		// 使用正则表达式提取端口号、协议和服务
		re := regexp.MustCompile(`([\w-]+)\s+(\d+)/(tcp|udp|sctp)\s+\d+\.\d+\s*#?\s*`)
		matches := re.FindStringSubmatch(line)

		// 如果匹配成功，提取端口号、协议、服务名
		if len(matches) >= 4 {
			port := matches[2]
			protocol := matches[3]
			serviceName := matches[1]

			// 将端口号转换为整数
			portInt := 0
			fmt.Sscanf(port, "%d", &portInt)

			// 初始化 map 结构
			mu.Lock()
			if _, exists := common.ServiceMap[portInt]; !exists {
				common.ServiceMap[portInt] = make(map[string]string)
			}
			// 存储协议和服务名
			common.ServiceMap[portInt][protocol] = serviceName
			mu.Unlock()
		}
	}

	// 检查是否有错误发生
	if err := scanner.Err(); err != nil {
		return err
	}
	logger.Infof("Service storage initialized successfully from %s", path)
	return nil
}

func firstExistingPath(candidates ...string) string {
	for _, p := range candidates {
		if p == "" {
			continue
		}
		clean := filepath.Clean(p)
		if _, err := os.Stat(clean); err == nil {
			return clean
		}
	}
	return ""
}
