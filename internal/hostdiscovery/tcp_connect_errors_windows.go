//go:build windows

package hostdiscovery

import (
	"errors"

	"golang.org/x/sys/windows"
)

func classifyPlatformTCPConnectError(err error) (tcpConnectErrorClass, bool) {
	switch {
	case errors.Is(err, windows.WSAECONNREFUSED):
		return tcpConnectMatched, true
	case errors.Is(err, windows.WSAETIMEDOUT),
		errors.Is(err, windows.WSAEHOSTUNREACH),
		errors.Is(err, windows.WSAENETDOWN),
		errors.Is(err, windows.WSAECONNRESET),
		errors.Is(err, windows.WSAECONNABORTED):
		return tcpConnectNoSignal, true
	case errors.Is(err, windows.WSAEACCES),
		errors.Is(err, windows.WSAEAFNOSUPPORT),
		errors.Is(err, windows.WSAEPROTONOSUPPORT),
		errors.Is(err, windows.WSAESOCKTNOSUPPORT):
		return tcpConnectUnavailable, true
	case errors.Is(err, windows.WSAENETUNREACH),
		errors.Is(err, windows.WSAEMFILE),
		errors.Is(err, windows.WSAENOBUFS),
		errors.Is(err, windows.WSAEADDRNOTAVAIL),
		errors.Is(err, windows.WSAEADDRINUSE):
		return tcpConnectFailed, true
	default:
		return tcpConnectFailed, false
	}
}
