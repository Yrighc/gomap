package assetprobe

import "encoding/json"

// ToJSON 将 ScanResult 序列化为 JSON 字节。
// 当 pretty=true 时输出格式化 JSON，便于日志与调试查看。
func (r *ScanResult) ToJSON(pretty bool) ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	if pretty {
		return json.MarshalIndent(r, "", "  ")
	}
	return json.Marshal(r)
}
