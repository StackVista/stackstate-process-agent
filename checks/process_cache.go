package checks

import (
	"time"

	"github.com/DataDog/gopsutil/cpu"
	"github.com/DataDog/gopsutil/process"
	"github.com/patrickmn/go-cache"
)

// ProcessMetrics is used to keep state of the previous cpu time and io stat counters so that we can calculate usage rate
type ProcessMetrics struct {
	CPUTime cpu.TimesStat
	IOStat  *process.IOCountersStat
}

// ProcessCache is used as the struct in the cache for all seen processes
type ProcessCache struct {
	ProcessMetrics ProcessMetrics
	FirstObserved  time.Time
	LastObserved   time.Time
}

// IsProcessCached checks whether the given process ID (pid + pidCreateTime) is present
func IsProcessCached(c *cache.Cache, fp *process.FilledProcess) (*ProcessCache, bool) {
	processID := createProcessID(fp.Pid, fp.CreateTime)

	cPointer, found := c.Get(processID)
	if found {
		return cPointer.(*ProcessCache), true
	}

	return nil, false
}

// PutProcessCache inserts or updates the ProcessCache for a given process ID (pid + pidCreateTime)
func PutProcessCache(c *cache.Cache, fp *process.FilledProcess) *ProcessCache {
	var cachedProcess *ProcessCache
	processID := createProcessID(fp.Pid, fp.CreateTime)
	now := time.Now()

	cPointer, found := c.Get(processID)
	if found {
		cachedProcess = cPointer.(*ProcessCache)
		cachedProcess.ProcessMetrics = ProcessMetrics{
			CPUTime: fp.CpuTime,
			IOStat:  fp.IOStat,
		}
		cachedProcess.LastObserved = now
	} else {
		cachedProcess = &ProcessCache{
			ProcessMetrics: ProcessMetrics{
				CPUTime: fp.CpuTime,
				IOStat:  fp.IOStat,
			},
			FirstObserved: now,
			LastObserved:  now,
		}
	}

	c.Set(processID, cachedProcess, cache.DefaultExpiration)
	return cachedProcess
}
