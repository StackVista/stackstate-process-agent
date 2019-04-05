// +build !linux_bpf,!windows

package config

type Config struct {
	CommonConfig
}

// DefaultConfig enables traffic collection for all connection types
var DefaultConfig = &Config{
	CommonConfig: *DefaultCommonConfig,
}

func MakeDefaultConfig() *Config {
	return &Config{
		CommonConfig: *MakeCommonConfig(),
	}
}
