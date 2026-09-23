//go:build !unix && !windows

package hostdiscovery

func classifyPlatformTCPConnectError(error) (tcpConnectErrorClass, bool) {
	return tcpConnectFailed, false
}
