package hostdiscovery

import "errors"

var (
	ErrModeUnavailable = errors.New("host discovery mode unavailable")
	ErrNoUsableModes   = errors.New("no usable host discovery modes")
)
