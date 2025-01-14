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
				r, err := state.readThrottledRatio()
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

type ThrottleState struct {
	nr_periods   uint64
	nr_throttled uint64
}

func newThrottleState() *ThrottleState {
	return &ThrottleState{}
}

func (t *ThrottleState) readThrottledRatio() (float64, error) {
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

	var nr_periods, nr_throttled uint64 = 0, 0

	// parse the cpu.stat
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Split(line, " ")
		if len(fields) >= 2 {
			if fields[0] == "nr_periods" {
				nr_periods, err = strconv.ParseUint(strings.TrimSpace(fields[1]), 10, 64)
			} else if fields[0] == "nr_throttled" {
				nr_throttled, err = strconv.ParseUint(strings.TrimSpace(fields[1]), 10, 64)
			}
		}
	}

	// No value found yet
	if t.nr_periods == 0 {
		t.nr_periods = nr_periods
		t.nr_throttled = nr_throttled
		return 0, nil
	}

	delta_periods := nr_periods - t.nr_periods
	delta_throttled := nr_throttled - t.nr_throttled

	if delta_periods == 0 {
		return 0, nil
	}

	t.nr_periods = nr_periods
	t.nr_throttled = nr_throttled

	return float64(delta_throttled) / float64(delta_periods), nil
}
