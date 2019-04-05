// +build linux_bpf

package checks

import (
	"bytes"

	"github.com/StackVista/stackstate-process-agent/pkg/tracer"
	tracerConfig "github.com/StackVista/stackstate-process-agent/pkg/tracer/config"
	log "github.com/cihub/seelog"
	"os"
)

// Init initializes a ConnectionsCheck instance.
func (c *pkg.ConnectionsCheck) Init(cfg *config.AgentConfig, sysInfo *pkg.SystemInfo) {
	var err error

	if cfg.EnableLocalNetworkTracer {
		log.Info("starting network tracer locally")
		c.useLocalTracer = true

		// Checking whether the current kernel version is supported by the tracer
		if _, err = tracer.IsTracerSupportedByOS(); err != nil {
			// err is always returned when false, so the above catches the !ok case as well
			log.Warnf("network tracer unsupported by OS: %s", err)
			return
		}

		conf := tracerConfig.DefaultConfig
		// This is what the process check uses to get /proc aswell, "github.com/DataDog/gopsutil/internal/common/common.go"
		// Unfortunately that is internal so i cannot use that here and we did not yet put stackstate-agent as a dependency
		if proc := os.Getenv("HOST_PROC"); proc != "" {
			conf.ProcRoot = proc
		}
		conf.MaxConnections = cfg.MaxPerMessage
		conf.BackfillFromProc = cfg.NetworkInitialConnectionsFromProc

		t, err := tracer.NewTracer(conf)
		if err != nil {
			log.Errorf("failed to create network tracer: %s", err)
			return
		}

		c.localTracer = t
		c.localTracer.Start()
	} else {
		// Calling the remote tracer will cause it to initialize and check connectivity
		pkg.SetNetworkTracerSocketPath(cfg.NetworkTracerSocketPath)
		pkg.GetRemoteNetworkTracerUtil()
	}

	c.buf = new(bytes.Buffer)
}
