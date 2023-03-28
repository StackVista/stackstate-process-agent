//go:build linux_bpf
// +build linux_bpf

package checks

import (
	"bytes"
	"github.com/DataDog/datadog-agent/pkg/network/tracer"
	"github.com/StackVista/stackstate-process-agent/pkg/pods"
	"time"

	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	log "github.com/cihub/seelog"
)

// Init initializes a ConnectionsCheck instance.
func (c *ConnectionsCheck) Init(cfg *config.AgentConfig, sysInfo *model.SystemInfo) {

	log.Info("starting network tracer locally")
	c.useLocalTracer = true

	// Checking whether the current kernel version is supported by the tracer
	if isSupported, reason := tracer.IsTracerSupportedByOS(nil); !isSupported {
		// err is always returned when false, so the above catches the !ok case as well
		c.localTracerErr = log.Errorf("network tracer unsupported by OS: %s. Set the environment STS_NETWORK_TRACING_ENABLED to false to disable network connections reporting", reason)
		return
	}

	conf := config.TracerConfig(cfg)

	t, err := retryTracerInit(cfg.NetworkTracerInitRetryDuration, cfg.NetworkTracerInitRetryAmount, conf, tracer.NewTracer)
	if err != nil {
		c.localTracerErr = log.Errorf("failed to create network tracer: %s.  Set the environment STS_NETWORK_TRACING_ENABLED to false to disable network connections reporting", err)
		return
	}

	c.podsCache = pods.MakeCachedPods(60 * time.Second)
	c.localTracer = t

	c.cache = NewNetworkRelationCache(cfg.NetworkRelationCacheDurationMin)

	c.buf = new(bytes.Buffer)
}
