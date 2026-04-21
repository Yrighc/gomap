package secprobe

import "encoding/json"

func marshalJSON(v any, pretty bool) ([]byte, error) {
	if pretty {
		return json.MarshalIndent(v, "", "  ")
	}
	return json.Marshal(v)
}

func (r *SecurityResult) ToJSON(pretty bool) ([]byte, error) { return marshalJSON(r, pretty) }
func (r *RunResult) ToJSON(pretty bool) ([]byte, error)      { return marshalJSON(r, pretty) }
