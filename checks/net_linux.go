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

		return fmt.Errorf("network tracer unsupported by OS: %s.", reason)
	}

	conf := config.TracerConfig(cfg)

	t, err := retryTracerInit(cfg.NetworkTracerInitRetryDuration, cfg.NetworkTracerInitRetryAmount, conf, tracer.NewTracer)
	if err != nil {
		return fmt.Errorf("failed to create network tracer: %s.", err)
	}

	// Get the root NS inode so that we will reuse it when formatting connections.
	rootHandle, err := kernel.GetRootNetNamespace(kernel.ProcFSRoot())
	if err != nil {
		return fmt.Errorf("Failed to get root net namespace handle: %v", err)
	}
	defer rootHandle.Close()

	c.rootNSIno, err = kernel.GetInoForNs(rootHandle)
	if err != nil {
		return fmt.Errorf("failed to get root network namespace inode: %s", err)
	}

	if cfg.NetworkTracer.PodCorrelation.Enabled {
		cfg.NetworkTracer.PodCorrelation.ObserverLogLevel = cfg.LogLevel
		c.podCorrelation, err = newPodCorrelationInfo(&cfg.NetworkTracer.PodCorrelation)
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
