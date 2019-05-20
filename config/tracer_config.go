package config

import (
	"io/ioutil"
	"os"
	"path/filepath"

	ddconfig "github.com/StackVista/stackstate-agent/pkg/config"
	"github.com/StackVista/stackstate-agent/pkg/util/log"

	"github.com/StackVista/stackstate-process-agent/ebpf"
	"github.com/StackVista/stackstate-process-agent/util"
)

// TracerConfigFromConfig returns a valid tracer-bpf config sourced from our agent config
func TracerConfigFromConfig(cfg *AgentConfig) *ebpf.Config {
	tracerConfig := ebpf.NewDefaultConfig()

	if !isIPv6EnabledOnHost() {
		tracerConfig.CollectIPv6Conns = false
		log.Info("network tracer IPv6 tracing disabled by system")
	} else if cfg.DisableIPv6Tracing {
		tracerConfig.CollectIPv6Conns = false
		log.Info("network tracer IPv6 tracing disabled by configuration")
	}

	if cfg.DisableUDPTracing {
		tracerConfig.CollectUDPConns = false
		log.Info("network tracer UDP tracing disabled by configuration")
	}

	if cfg.DisableTCPTracing {
		tracerConfig.CollectTCPConns = false
		log.Info("network tracer TCP tracing disabled by configuration")
	}

	if cfg.CollectLocalDNS {
		tracerConfig.CollectLocalDNS = true
	}

	tracerConfig.MaxTrackedConnections = cfg.MaxTrackedConnections
	tracerConfig.ProcRoot = getProcRoot()

	return tracerConfig
}

func isIPv6EnabledOnHost() bool {
	_, err := ioutil.ReadFile(filepath.Join(getProcRoot(), "net/if_inet6"))
	return err == nil
}

func getProcRoot() string {
	if v := os.Getenv("HOST_PROC"); v != "" {
		return v
	}

	if ddconfig.IsContainerized() && util.PathExists("/host") {
		return "/host/proc"
	}

	return "/proc"
}
