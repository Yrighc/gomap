package hostdiscovery

import "errors"

var (
	ErrModeUnavailable = errors.New("host discovery mode unavailable")
	ErrProbeFailed     = errors.New("host discovery probe failed")
	ErrInvalidOptions  = errors.New("invalid host discovery options")
	ErrNoUsableModes   = errors.New("no usable host discovery modes")
)
