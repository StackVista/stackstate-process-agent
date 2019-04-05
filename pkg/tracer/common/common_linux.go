//+build linux_bpf

package common

import (
	bpflib "github.com/iovisor/gobpf/elf"
	"os"
)

const (
	V4UDPMapName           = "udp_stats_ipv4"
	V6UDPMapName           = "udp_stats_ipv6"
	V4TCPMapName           = "tcp_stats_ipv4"
	V6TCPMapName           = "tcp_stats_ipv6"
	LatestTimestampMapName = "latest_ts"
	// maxActive configures the maximum number of instances of the kretprobe-probed functions handled simultaneously.
	// This value should be enough for typical workloads (e.g. some amount of processes blocked on the accept syscall).
	MaxActive = 256
)

var (
	// Feature versions sourced from: https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md
	// Minimum kernel version -> max(3.15 - eBPF,
	//                               3.18 - tables/maps,
	//                               4.1 - kprobes,
	//                               4.3 - perf events)
	// 	                      -> 4.3
	MinRequiredKernelCode = LinuxKernelVersionCode(4, 3, 0)
)

// KERNEL_VERSION(a,b,c) = (a << 16) + (b << 8) + (c)
// Per https://github.com/torvalds/linux/blob/master/Makefile#L1187
func LinuxKernelVersionCode(major, minor, patch uint32) uint32 {
	return (major << 16) + (minor << 8) + patch
}

// CurrentKernelVersion exposes calculated kernel version - exposed in LINUX_VERSION_CODE format
// That is, for kernel "a.b.c", the version number will be (a<<16 + b<<8 + c)
func CurrentKernelVersion() (uint32, error) {
	return bpflib.CurrentKernelVersion()
}

func TestRoot() string {
	if procRoot, isSet := os.LookupEnv("TEST_PROC_ROOT"); isSet {
		return procRoot
	}
	return "/proc"
}
