// +build linux_bpf

package config

type Config struct {
	CommonConfig
	// BackfillFromProc enables using /proc to find connections which were already active when the tracer started
	BackfillFromProc bool
	// Location of /proc
	ProcRoot string
}

// DefaultConfig enables traffic collection for all connection types
var DefaultConfig = &Config{
	CommonConfig:     *DefaultCommonConfig,
	BackfillFromProc: true,
	ProcRoot:         "/proc",
}

func MakeDefaultConfig() *Config {
	return &Config{
		CommonConfig:     *MakeCommonConfig(),
		BackfillFromProc: true,
		ProcRoot:         "/proc",
	}
}
