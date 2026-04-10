package service

// 解析 gomap-services 文件，存储端口对应的服务信息
import (
	"bufio"
	"fmt"
	"github.com/yrighc/gomap/config/common"
	"github.com/yrighc/gomap/config/logger"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := loadServiceStorage(file); err != nil {
		return err
	}
	logger.Infof("Service storage initialized successfully from %s", path)
	return nil
}

func ServiceStorageFromBytes(data []byte, source string) error {
	if source == "" {
		source = "embedded"
	}
	if err := loadServiceStorage(strings.NewReader(string(data))); err != nil {
		return err
	}
	logger.Infof("Service storage initialized successfully from %s", source)
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

func loadServiceStorage(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		if len(line) == 0 || line[0] == '#' {
			continue
		}

		re := regexp.MustCompile(`([\w-]+)\s+(\d+)/(tcp|udp|sctp)\s+\d+\.\d+\s*#?\s*`)
		matches := re.FindStringSubmatch(line)

		if len(matches) >= 4 {
			port := matches[2]
			protocol := matches[3]
			serviceName := matches[1]

			portInt := 0
			fmt.Sscanf(port, "%d", &portInt)

			mu.Lock()
			if _, exists := common.ServiceMap[portInt]; !exists {
				common.ServiceMap[portInt] = make(map[string]string)
			}
			common.ServiceMap[portInt][protocol] = serviceName
			mu.Unlock()
		}
	}

	return scanner.Err()
}
