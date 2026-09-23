package hostdiscovery

import (
	"errors"
	"net"
)

func isNetworkTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
