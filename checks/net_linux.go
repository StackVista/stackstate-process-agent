//go:build linux_bpf
// +build linux_bpf

package checks

import (
	"bytes"
	"fmt"
	"time"

	"github.com/DataDog/datadog-agent/pkg/network/tracer"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/StackVista/stackstate-process-agent/pkg/pods"
	log "github.com/cihub/seelog"
)

// Init initializes a ConnectionsCheck instance.
func (c *ConnectionsCheck) Init(cfg *config.AgentConfig, _ *model.SystemInfo) error {

	log.Info("starting network tracer locally")

	// Checking whether the current kernel version is supported by the tracer
	if isSupported, reason := tracer.IsTracerSupportedByOS(nil); !isSupported {

		return fmt.Errorf("network tracer unsupported by OS: %s. Set the environment STS_NETWORK_TRACING_ENABLED to false to disable network connections reporting", reason)
	}

	conf := config.TracerConfig(cfg)

	t, err := retryTracerInit(cfg.NetworkTracerInitRetryDuration, cfg.NetworkTracerInitRetryAmount, conf, tracer.NewTracer)
	if err != nil {
		return fmt.Errorf("failed to create network tracer: %s.  Set the environment STS_NETWORK_TRACING_ENABLED to false to disable network connections reporting", err)
	}

	if cfg.NetworkTracer.PodCorrelation.Enabled {
		rootHandle, err := kernel.GetRootNetNamespace(kernel.ProcFSRoot())
		if err != nil {
			return fmt.Errorf("Failed to get root net namespace: %v", err)
		}

		ino, err := kernel.GetInoForNs(rootHandle)
		if err != nil {
			return fmt.Errorf("Failed to get inode for root net namespace: %v", err)
		}

		c.podCorrelation, err = newPodCorrelationInfo(&cfg.NetworkTracer.PodCorrelation, cfg.LogLevel, ino)
		if err != nil {
			return err
		}
	}

	c.podsCache = pods.MakeCachedPods(60 * time.Second)
	c.localTracer = t

	c.cache = NewNetworkRelationCache(cfg.NetworkRelationCacheDurationMin)

	c.buf = new(bytes.Buffer)

	return nil
}
