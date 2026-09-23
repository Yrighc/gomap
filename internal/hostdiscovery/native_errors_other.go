//go:build !linux && !darwin

package hostdiscovery

import (
	"errors"
	"os"
)

func isNativeCapabilityError(err error) bool {
	return errors.Is(err, os.ErrPermission)
}
