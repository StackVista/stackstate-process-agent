package checks

import (
	"bytes"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/StackVista/stackstate-process-agent/net"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer"
	tracerConfig "github.com/StackVista/tcptracer-bpf/pkg/tracer/config"
	log "github.com/cihub/seelog"
)

// Init initializes a ConnectionsCheck instance.
func (c *ConnectionsCheck) Init(cfg *config.AgentConfig, sysInfo *model.SystemInfo) {
	var err error

	if cfg.EnableLocalNetworkTracer {
		log.Info("starting network tracer locally")
		c.useLocalTracer = true

		// Checking whether the current kernel version is supported by the tracer
		if _, err = tracer.IsTracerSupportedByOS(); err != nil {
			// err is always returned when false, so the above catches the !ok case as well
			log.Errorf("network tracer unsupported by OS: %s. Set the environment STS_NETWORK_TRACING_ENABLED to false to disable network connections reporting", err)
			return
		}

		conf := tracerConfig.DefaultConfig
		conf.MaxConnections = cfg.NetworkTracerMaxConnections

		t, err := tracer.NewTracer(conf)
		if err != nil {
			log.Errorf("failed to create network tracer: %s. Set the environment STS_NETWORK_TRACING_ENABLED to false to disable network connections reporting", err)
			return
		}

		c.localTracer = t
		c.localTracer.Start()
	} else {
		// Calling the remote tracer will cause it to initialize and check connectivity
		net.SetNetworkTracerSocketPath(cfg.NetworkTracerSocketPath)
		net.GetRemoteNetworkTracerUtil()
	}

	c.cache = NewNetworkRelationCache(cfg.NetworkRelationCacheDurationMin)

	c.buf = new(bytes.Buffer)
}
