package debug

import (
	"fmt"
	log "github.com/cihub/seelog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DetectThrottle detects whether cgroups is being throttled and logs a warning.
func DetectThrottle(initialDelay, interval time.Duration) func() {
	state := newThrottleState()

	doneChannel := make(chan interface{})

	log.Info("Watching for throttling")

	go func() {
		time.Sleep(initialDelay)
		for {
			select {
			case <-time.NewTicker(interval).C:
				ratio, err := state.readThrottledRatio()
				if err != nil {
					log.Warnf("Error reading throttle information form cgroup. Exiting throttle watcher: %v", err)
				}
				if r > 0.7 {
					log.Warn("Detected throttling (more than 70% of periods were throttled). Please increase cpu limits.")
				}
			case <-doneChannel:
				break
			}
		}
	}()

	return func() {
		log.Info("Stopping throttle detection")
		doneChannel <- struct{}{}
	}
}

// getCgroupPath returns the cgroup path for the current process
func getCgroupPath() (string, error) {
	proc := "/proc"
	if v := os.Getenv("HOST_PROC"); v != "" {
		proc = v
	}

	// Read the current process's cgroup file
	data, err := os.ReadFile(filepath.Join(proc, "self", "cgroup"))
	if err != nil {
		return "", fmt.Errorf("failed to read cgroup file: %v", err)
	}

	// Parse the cgroup path
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 3 {
			return fields[2], nil
		}
	}
	return "", fmt.Errorf("no valid cgroup path found")
}

type throttleState struct {
	nrPeriods   uint64
	nrThrottled uint64
}

func newThrottleState() *throttleState {
	return &throttleState{}
}

func (t *throttleState) readThrottledRatio() (float64, error) {
	cgroupPath, err := getCgroupPath()
	if err != nil {
		return 0, err
	}

	sys := "/sys"
	if v := os.Getenv("HOST_SYS"); v != "" {
		sys = v
	}

	data, err := os.ReadFile(filepath.Join(sys, "fs/cgroup", cgroupPath, "cpu.stat"))
	if err != nil {
		return 0, err
	}

	var nrPeriods, nrThrottled uint64 = 0, 0

	// parse the cpu.stat
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Split(line, " ")
		if len(fields) >= 2 {
			if fields[0] == "nr_periods" {
				nrPeriods, err = strconv.ParseUint(strings.TrimSpace(fields[1]), 10, 64)
			} else if fields[0] == "nrThrottled" {
				nrThrottled, err = strconv.ParseUint(strings.TrimSpace(fields[1]), 10, 64)
			}
		}
	}

	// No value found yet
	if t.nrPeriods == 0 {
		t.nrPeriods = nrPeriods
		t.nrThrottled = nrThrottled
		return 0, nil
	}

	deltaPeriods := nrPeriods - t.nrPeriods
	deltaThrottled := nrThrottled - t.nrThrottled

	if deltaPeriods == 0 {
		return 0, nil
	}

	t.nrPeriods = nrPeriods
	t.nrThrottled = nrThrottled

	return float64(deltaThrottled) / float64(deltaPeriods), nil
}
