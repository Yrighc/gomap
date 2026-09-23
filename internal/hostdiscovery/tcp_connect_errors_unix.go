//go:build unix

package hostdiscovery

import (
	"errors"

	"golang.org/x/sys/unix"
)

func classifyPlatformTCPConnectError(err error) (tcpConnectErrorClass, bool) {
	switch {
	case errors.Is(err, unix.ECONNREFUSED):
		return tcpConnectMatched, true
	case errors.Is(err, unix.ETIMEDOUT),
		errors.Is(err, unix.EHOSTUNREACH),
		errors.Is(err, unix.ENETDOWN),
		errors.Is(err, unix.EHOSTDOWN),
		errors.Is(err, unix.ECONNRESET),
		errors.Is(err, unix.ECONNABORTED):
		return tcpConnectNoSignal, true
	case errors.Is(err, unix.EACCES),
		errors.Is(err, unix.EPERM),
		errors.Is(err, unix.EAFNOSUPPORT),
		errors.Is(err, unix.EPROTONOSUPPORT),
		errors.Is(err, unix.ESOCKTNOSUPPORT):
		return tcpConnectUnavailable, true
	case errors.Is(err, unix.ENETUNREACH),
		errors.Is(err, unix.EMFILE),
		errors.Is(err, unix.ENFILE),
		errors.Is(err, unix.ENOBUFS),
		errors.Is(err, unix.ENOMEM),
		errors.Is(err, unix.EADDRNOTAVAIL),
		errors.Is(err, unix.EADDRINUSE),
		errors.Is(err, unix.EAGAIN):
		return tcpConnectFailed, true
	default:
		return tcpConnectFailed, false
	}
}
