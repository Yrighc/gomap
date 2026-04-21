package assetprobe

import "encoding/json"

// MarshalJSON serializes a Go value into JSON bytes.
// When pretty=true it returns indented output for CLI and debugging use.
func MarshalJSON(v any, pretty bool) ([]byte, error) {
	if v == nil {
		return []byte("null"), nil
	}
	if pretty {
		return json.MarshalIndent(v, "", "  ")
	}
	return json.Marshal(v)
}

// ToJSON 将 ScanResult 序列化为 JSON 字节。
// 当 pretty=true 时输出格式化 JSON，便于日志与调试查看。
func (r *ScanResult) ToJSON(pretty bool) ([]byte, error) {
	return MarshalJSON(r, pretty)
}

// ToJSON 将 BatchScanResult 序列化为 JSON 字节。
// 当 pretty=true 时输出格式化 JSON，便于日志与调试查看。
func (r *BatchScanResult) ToJSON(pretty bool) ([]byte, error) {
	return MarshalJSON(r, pretty)
}

// ToJSON 将 HomepageResult 序列化为 JSON 字节。
// 当 pretty=true 时输出格式化 JSON，便于日志与调试查看。
func (r *HomepageResult) ToJSON(pretty bool) ([]byte, error) {
	return MarshalJSON(r, pretty)
}

// ToJSON 将 DirResult 序列化为 JSON 字节。
// 当 pretty=true 时输出格式化 JSON，便于日志与调试查看。
func (r *DirResult) ToJSON(pretty bool) ([]byte, error) {
	return MarshalJSON(r, pretty)
}
