package secprobe

import (
	"strings"

	appassets "github.com/yrighc/gomap/app"
)

func BuiltinCredentials(protocol string) ([]Credential, error) {
	data, err := appassets.SecprobeDict(strings.ToLower(strings.TrimSpace(protocol)))
	if err != nil {
		return nil, err
	}
	return parseCredentialLines(string(data))
}

func parseCredentialLines(raw string) ([]Credential, error) {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	out := make([]Credential, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, " : ", 2)
		if len(parts) != 2 {
			continue
		}
		out = append(out, Credential{
			Username: strings.TrimSpace(parts[0]),
			Password: strings.TrimSpace(parts[1]),
		})
	}
	return out, nil
}
