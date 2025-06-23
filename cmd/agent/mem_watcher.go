package main

import (
	"math"
	"runtime"
	"runtime/debug"
	"time"

	log "github.com/cihub/seelog"
)

const (
	threshold = 0.95            // Default threshold for GOMEMLIMIT watcher
	interval  = 1 * time.Minute // This interval should allow us to get a log before the container is OOMKilled
)

func bytesToMB(bytes uint64) float64 {
	return float64(bytes) / (1024 * 1024)
}

// run is the monitoring loop executed in a goroutine.
func runMemWatcher() {
	// -1 does not set a limit, but returns the current GOMEMLIMIT.
	limit := debug.SetMemoryLimit(-1)
	if limit == int64(math.MaxInt64) {
		log.Info("memory limit is not set or is disabled, no need to run the watcher")
		return
	}

	log.Infof("starting memWatcher, limit detected: %f MB", bytesToMB(uint64(limit)))

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var memStats runtime.MemStats
	thresholdBytes := uint64(float64(limit) * threshold)

	for range ticker.C {
		runtime.ReadMemStats(&memStats)
		// The limit includes all memory mapped, managed, and not released by the Go runtime.
		// So we try to recover this value from the runtime.
		// See here for more details: https://pkg.go.dev/runtime/debug@go1.24.4#SetMemoryLimit
		mem := memStats.Sys - memStats.HeapReleased
		if mem >= thresholdBytes {
			log.Warnf(`memory usage is over (%f * GOMEMLIMIT)! Current usage: %f MB, GOMEMLIMIT: %f MB`, threshold,
				bytesToMB(mem), bytesToMB(uint64(limit)))
		} else {
			log.Infof("memory usage: %f MB", bytesToMB(mem))
		}
	}
}
