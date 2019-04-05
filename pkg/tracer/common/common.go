//+build !linux_bpf

package common

func LinuxKernelVersionCode(major, minor, patch uint32) uint32 {
	return 0
}

func CurrentKernelVersion() (uint32, error) {
	return 0, ErrNotImplemented
}
