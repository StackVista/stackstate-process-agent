//go:build linux_bpf
// +build linux_bpf

package checks

import (
	"bytes"
	tracerConfig "github.com/StackVista/stackstate-agent/pkg/network/config"
	tracer2 "github.com/StackVista/stackstate-agent/pkg/network/tracer"
	"os"

	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/StackVista/stackstate-process-agent/net"
	log "github.com/cihub/seelog"
)

// Init initializes a ConnectionsCheck instance.
func (c *ConnectionsCheck) Init(cfg *config.AgentConfig, sysInfo *model.SystemInfo) {

	if cfg.EnableLocalNetworkTracer {
		log.Info("starting network tracer locally")
		c.useLocalTracer = true

		// Checking whether the current kernel version is supported by the tracer
		if isSupported, reason := tracer2.IsTracerSupportedByOS(nil); !isSupported {
			// err is always returned when false, so the above catches the !ok case as well
			c.localTracerErr = log.Errorf("network tracer unsupported by OS: %s. Set the environment STS_NETWORK_TRACING_ENABLED to false to disable network connections reporting", reason)
			return
		}

		conf := tracerConfig.New()
		// This is what the process check uses to get /proc aswell, "github.com/DataDog/gopsutil/internal/common/common.go"
		// Unfortunately that is internal so i cannot use that here and we did not yet put stackstate-agent as a dependency
		if proc := os.Getenv("HOST_PROC"); proc != "" {
			conf.ProcRoot = proc
		}
		conf.MaxTrackedConnections = uint(cfg.NetworkTracerMaxConnections) // TODO make sure it is the same
		conf.EnableHTTPMonitoring = cfg.NetworkTracer.EnableProtocolInspection
		conf.EnableHTTPSMonitoring = cfg.NetworkTracer.EnableProtocolInspection
		// TODO *cfg.NetworkTracer.HTTPMetrics
		//conf.BackfillFromProc = cfg.NetworkInitialConnectionsFromProc
		//conf.EnableTracepipeLogging = cfg.NetworkTracer.EbpfDebuglogEnabled

		t, err := retryTracerInit(cfg.NetworkTracerInitRetryDuration, cfg.NetworkTracerInitRetryAmount, conf, tracer2.NewTracer)
		if err != nil {
			c.localTracerErr = log.Errorf("failed to create network tracer: %s.  Set the environment STS_NETWORK_TRACING_ENABLED to false to disable network connections reporting", err)
			return
		}

		c.localTracer = t
	} else {
		// Calling the remote tracer will cause it to initialize and check connectivity
		net.SetNetworkTracerSocketPath(cfg.NetworkTracerSocketPath)
		net.GetRemoteNetworkTracerUtil()
	}

	c.cache = NewNetworkRelationCache(cfg.NetworkRelationCacheDurationMin)

	c.buf = new(bytes.Buffer)
}
