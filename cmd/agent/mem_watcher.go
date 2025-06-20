package main

import (
	"math"
	"runtime"
	"runtime/debug"
	"time"

	log "github.com/cihub/seelog"
)

const (
	threshold = 0.9             // Default threshold for GOMEMLIMIT watcher (90%)
	interval  = 5 * time.Minute // Default check interval
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
		// we want to see all memory not yet freed by the GC.
		heapAlloc := memStats.HeapAlloc
		log.Infof("allocated heap objects: %f MB", bytesToMB(heapAlloc))
		if heapAlloc >= thresholdBytes {
			log.Warnf(`heap memory usage is over (%f * GOMEMLIMIT)! Current usage: %f MB, GOMEMLIMIT: %f MB`, threshold,
				bytesToMB(heapAlloc), bytesToMB(uint64(limit)))
		}
	}
}
