package httpauth

import (
	"net/http"
	"time"
)

type Config struct {
	Timeout            time.Duration
	InsecureSkipVerify bool
}

type Request struct {
	Method string
	URL    string
	Header http.Header
	Body   []byte
}

type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}
