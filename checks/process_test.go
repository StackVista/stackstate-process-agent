package checks

import (
	"github.com/DataDog/gopsutil/cpu"
	"github.com/StackVista/stackstate-agent/pkg/util/containers"
	"github.com/StackVista/stackstate-process-agent/config"
	"regexp"
	"sort"

	// "regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	// "github.com/DataDog/gopsutil/cpu"
	"github.com/DataDog/gopsutil/process"
	//	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/stretchr/testify/assert"
	// "github.com/StackVista/stackstate-agent/pkg/util/containers"
)

func makeProcess(pid int32, cmdline string) *process.FilledProcess {
	return &process.FilledProcess{
		Pid:         pid,
		Cmdline:     strings.Split(cmdline, " "),
		MemInfo:     &process.MemoryInfoStat{},
		CtxSwitches: &process.NumCtxSwitchesStat{},
	}
}

func makeProcessWithResource(pid int32, cmdline string, resMemory, readCount, writeCount uint64, userCPU, systemCPU float64) *process.FilledProcess {
	return &process.FilledProcess{
		Pid:         pid,
		Cmdline:     strings.Split(cmdline, " "),
		MemInfo:     &process.MemoryInfoStat{RSS: resMemory},
		CtxSwitches: &process.NumCtxSwitchesStat{},
		IOStat:      &process.IOCountersStat{ReadCount: readCount, WriteCount: writeCount},
		CpuTime: cpu.TimesStat{
			User: userCPU, System: systemCPU, Nice: 0, Iowait: 0, Irq: 0, Softirq: 0, Steal: 0, Guest: 0,
			GuestNice: 0, Idle: 0, Stolen: 0,
		},
	}
}

func TestProcessFiltering(t *testing.T) {
	pNow := []*process.FilledProcess{
		// generic processes
		makeProcessWithResource(1, "git clone google.com", 0, 0, 0, 0, 0),
		makeProcessWithResource(2, "mine-bitcoins -all -x", 0, 0, 0, 0, 0),
		makeProcessWithResource(3, "datadog-process-agent -ddconfig datadog.conf", 0, 0, 0, 0, 0),
		makeProcessWithResource(4, "foo -bar -bim", 0, 0, 0, 0, 0),
		// resource intensive processes
		// cpu resource intensive processes
		makeProcessWithResource(5, "cpu resource process 1", 0, 0, 0, 20, 20),
		makeProcessWithResource(6, "cpu resource process 2", 0, 0, 0, 35, 60),
		makeProcessWithResource(7, "cpu resource process 3", 0, 0, 0, 11, 15),
		makeProcessWithResource(8, "cpu resource process 4", 0, 0, 0, 26, 12),
		makeProcessWithResource(9, "cpu resource process 5", 0, 0, 0, 21, 16),
		// memory resource intensive processes
		makeProcessWithResource(10, "memory resource process 1", 50, 0, 0, 0, 0),
		makeProcessWithResource(11, "memory resource process 2", 150, 0, 0, 0, 0),
		makeProcessWithResource(12, "memory resource process 3", 100, 0, 0, 0, 0),
		makeProcessWithResource(13, "memory resource process 4", 200, 0, 0, 0, 0),
		// read io resource intensive processes
		makeProcessWithResource(14, "read io resource process 1", 0, 80, 0, 0, 0),
		makeProcessWithResource(15, "read io resource process 2", 0, 40, 0, 0, 0),
		makeProcessWithResource(16, "read io resource process 3", 0, 120, 0, 0, 0),
		makeProcessWithResource(17, "read io resource process 4", 0, 90, 0, 0, 0),
		// write io resource intensive processes
		makeProcessWithResource(18, "write io resource process 1", 0, 0, 20, 0, 0),
		makeProcessWithResource(19, "write io resource process 2", 0, 0, 60, 0, 0),
		makeProcessWithResource(20, "write io resource process 3", 0, 0, 80, 0, 0),
		makeProcessWithResource(21, "write io resource process 4", 0, 0, 70, 0, 0),
	}
	pLast := []*process.FilledProcess{
		// generic processes
		makeProcessWithResource(1, "git clone google.com", 0, 0, 0, 0, 0),
		makeProcessWithResource(2, "mine-bitcoins -all -x", 0, 0, 0, 0, 0),
		makeProcessWithResource(3, "datadog-process-agent -ddconfig datadog.conf", 0, 0, 0, 0, 0),
		makeProcessWithResource(4, "foo -bar -bim", 0, 0, 0, 0, 0),
		// resource intensive processes
		// cpu resource intensive processes
		makeProcessWithResource(5, "cpu resource process 1", 0, 0, 0, 4, 10),
		makeProcessWithResource(6, "cpu resource process 2", 0, 0, 0, 4, 10),
		makeProcessWithResource(7, "cpu resource process 3", 0, 0, 0, 4, 10),
		makeProcessWithResource(8, "cpu resource process 4", 0, 0, 0, 4, 10),
		makeProcessWithResource(9, "cpu resource process 5", 0, 0, 0, 4, 10),
		// memory resource intensive processes
		makeProcessWithResource(10, "memory resource process 1", 50, 0, 0, 0, 0),
		makeProcessWithResource(11, "memory resource process 2", 150, 0, 0, 0, 0),
		makeProcessWithResource(12, "memory resource process 3", 100, 0, 0, 0, 0),
		makeProcessWithResource(13, "memory resource process 4", 200, 0, 0, 0, 0),
		// read io resource intensive processes
		makeProcessWithResource(14, "read io resource process 1", 0, 10, 0, 0, 0),
		makeProcessWithResource(15, "read io resource process 2", 0, 10, 0, 0, 0),
		makeProcessWithResource(16, "read io resource process 3", 0, 10, 0, 0, 0),
		makeProcessWithResource(17, "read io resource process 4", 0, 10, 0, 0, 0),
		// write io resource intensive processes
		makeProcessWithResource(18, "write io resource process 1", 0, 0, 10, 0, 0),
		makeProcessWithResource(19, "write io resource process 2", 0, 0, 10, 0, 0),
		makeProcessWithResource(20, "write io resource process 3", 0, 0, 10, 0, 0),
		makeProcessWithResource(21, "write io resource process 4", 0, 0, 10, 0, 0),
	}
	containers := []*containers.Container{}
	lastRun := time.Now().Add(-5 * time.Second)
	syst1, syst2 := cpu.TimesStat{
		User: 10, System: 20, Nice: 0, Iowait: 0, Irq: 0, Softirq: 0, Steal: 0, Guest: 0,
		GuestNice: 0, Idle: 0, Stolen: 0,
	}, cpu.TimesStat{
		User: 20, System: 40, Nice: 0, Iowait: 0, Irq: 0, Softirq: 0, Steal: 0, Guest: 0,
		GuestNice: 0, Idle: 0, Stolen: 0,
	}
	cfg := config.NewDefaultAgentConfig()

	for i, tc := range []struct {
		cur, last                   []*process.FilledProcess
		maxSize                     int
		blacklist                   []string
		expectedTotal               int
		expectedChunks              int
		amountTopCPUPercentageUsage int
		amountTopIOReadUsage        int
		amountTopIOWriteUsage       int
		amountTopMemoryUsage        int
		expectedPids                []int32
	}{
		// expects all the processes to be present and chunked into 3 processes per chunk
		{
			cur:                         pNow,
			last:                        pLast,
			maxSize:                     3,
			blacklist:                   []string{},
			expectedTotal:               21,
			expectedChunks:              7,
			amountTopCPUPercentageUsage: 2,
			amountTopIOReadUsage:        2,
			amountTopIOWriteUsage:       2,
			amountTopMemoryUsage:        2,
			expectedPids:                []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21},
		},
		// expects all the processes not listed in the blacklist to be present as well as the top resource consuming
		// processes regardless of whether they are blacklisted or not
		{
			cur:                         pNow,
			last:                        pLast,
			maxSize:                     3,
			blacklist:                   []string{"resource process"},
			expectedTotal:               12,
			expectedChunks:              4,
			amountTopCPUPercentageUsage: 2,
			amountTopIOReadUsage:        2,
			amountTopIOWriteUsage:       2,
			amountTopMemoryUsage:        2,
			expectedPids:                []int32{1, 2, 3, 4, 5, 6, 11, 13, 16, 17, 20, 21},
		},
		// expects all the top resource consuming process only to be present in a single chunk
		{
			cur:                         pNow,
			last:                        pLast,
			maxSize:                     7,
			blacklist:                   []string{"resource process", "git", "datadog", "foo", "mine"},
			expectedTotal:               7,
			expectedChunks:              1,
			amountTopCPUPercentageUsage: 2,
			amountTopIOReadUsage:        1,
			amountTopIOWriteUsage:       1,
			amountTopMemoryUsage:        3,
			expectedPids:                []int32{5, 6, 11, 12, 13, 16, 20},
		},
	} {
		bl := make([]*regexp.Regexp, 0, len(tc.blacklist))
		for _, s := range tc.blacklist {
			bl = append(bl, regexp.MustCompile(s))
		}
		cfg.Blacklist = bl
		cfg.MaxPerMessage = tc.maxSize

		cfg.AmountTopCPUPercentageUsage = tc.amountTopCPUPercentageUsage
		cfg.AmountTopMemoryUsage = tc.amountTopMemoryUsage
		cfg.AmountTopIOReadUsage = tc.amountTopIOReadUsage
		cfg.AmountTopIOWriteUsage = tc.amountTopIOWriteUsage

		cur := make(map[int32]*process.FilledProcess)
		for _, c := range tc.cur {
			cur[c.Pid] = c
		}
		last := make(map[int32]*process.FilledProcess)
		for _, c := range tc.last {
			last[c.Pid] = c
		}

		chunked := fmtProcesses(cfg, cur, last, containers, syst2, syst1, lastRun)
		assert.Len(t, chunked, tc.expectedChunks, "len %d", i)
		total := 0
		pids := make([]int32, 0)
		for _, c := range chunked {
			total += len(c)
			for _, proc := range c {
				pids = append(pids, proc.Pid)
			}
		}
		assert.Equal(t, tc.expectedTotal, total, "total test %d", i)
		sort.Slice(pids, func(i, j int) bool {
			return pids[i] < pids[j]
		})
		assert.Equal(t, tc.expectedPids, pids, "expected pIds: %v, found pIds: %v", tc.expectedPids, pids)

		chunkedStat := fmtProcessStats(cfg, cur, last, containers, syst2, syst1, lastRun)
		assert.Len(t, chunkedStat, tc.expectedChunks, "len stat %d", i)
		total = 0
		pids = make([]int32, 0)
		for _, c := range chunkedStat {
			total += len(c)
			for _, proc := range c {
				pids = append(pids, proc.Pid)
			}
		}
		assert.Equal(t, tc.expectedTotal, total, "total stat test %d", i)
		sort.Slice(pids, func(i, j int) bool {
			return pids[i] < pids[j]
		})
		assert.Equal(t, tc.expectedPids, pids, "expected pIds: %v, found pIds: %v", tc.expectedPids, pids)
	}
}

func TestPercentCalculation(t *testing.T) {
	// Capping at NUM CPU * 100 if we get odd values for delta-{Proc,Time}
	assert.True(t, floatEquals(calculatePct(100, 50, 1), 100))

	// Zero deltaTime case
	assert.True(t, floatEquals(calculatePct(100, 0, 8), 0.0))

	assert.True(t, floatEquals(calculatePct(0, 8.08, 8), 0.0))
	if runtime.GOOS != "windows" {
		assert.True(t, floatEquals(calculatePct(100, 200, 2), 100))
		assert.True(t, floatEquals(calculatePct(0.04, 8.08, 8), 3.960396))
		assert.True(t, floatEquals(calculatePct(1.09, 8.08, 8), 107.920792))
	}
}

func TestRateCalculation(t *testing.T) {
	now := time.Now()
	prev := now.Add(-1 * time.Second)
	var empty time.Time
	assert.True(t, floatEquals(calculateRate(5, 1, prev), 4))
	assert.True(t, floatEquals(calculateRate(5, 1, prev.Add(-2*time.Second)), float32(1.33333333)))
	assert.True(t, floatEquals(calculateRate(5, 1, now), 0))
	assert.True(t, floatEquals(calculateRate(5, 0, prev), 0))
	assert.True(t, floatEquals(calculateRate(5, 1, empty), 0))
}

func floatEquals(a, b float32) bool {
	var e float32 = 0.00000001 // Difference less than some epsilon
	return a-b < e && b-a < e
}
