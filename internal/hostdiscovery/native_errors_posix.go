//go:build linux || darwin

package hostdiscovery

import (
	"errors"
	"os"
	"syscall"
)

func isNativeCapabilityError(err error) bool {
	return errors.Is(err, os.ErrPermission) ||
		errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.EAFNOSUPPORT) ||
		errors.Is(err, syscall.EPROTONOSUPPORT) ||
		errors.Is(err, syscall.ENOPROTOOPT)
}
