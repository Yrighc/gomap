//go:build linux

package hostdiscovery

func newTCPSYNRunner(opts Options) Runner {
	return newNativeTCPRunner("tcp-syn", opts, openLinuxNativeTCPSession)
}

func newTCPACKRunner(opts Options) Runner {
	return newNativeTCPRunner("tcp-ack", opts, openLinuxNativeTCPSession)
}

func newARPRunner(opts Options) Runner {
	return newLinuxARPRunner(opts)
}
