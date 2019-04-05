package checks

import (
	"fmt"
	"github.com/StackVista/stackstate-process-agent/pkg/config"
	"github.com/StackVista/stackstate-process-agent/pkg/util"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/gopsutil/cpu"
	"github.com/DataDog/gopsutil/process"
	"github.com/StackVista/stackstate-agent/pkg/util/containers"
	"github.com/StackVista/stackstate-process-agent/pkg/model"
)

func procCtrGenerator(pCount int, cCount int, containeredProcs int) ([]*process.FilledProcess, []*containers.Container) {
	procs := make([]*process.FilledProcess, 0, pCount)
	for i := 0; i < pCount; i++ {
		procs = append(procs, makeProcess(int32(i), strconv.Itoa(i)))
	}

	ctrs := make([]*containers.Container, 0, cCount)
	for i := 0; i < cCount; i++ {
		ctrs = append(ctrs, makeContainer(strconv.Itoa(i)))
	}

	// build container process relationship
	ctrIdx := 0
	for i := 0; i < containeredProcs; i++ {
		// reset to 0 if hit the last one
		if ctrIdx == cCount {
			ctrIdx = 0
		}
		ctrs[ctrIdx].Pids = append(ctrs[ctrIdx].Pids, procs[i].Pid)
		ctrIdx++
	}

	return procs, ctrs
}

func procsToHash(procs []*process.FilledProcess) (procsByPid map[int32]*process.FilledProcess) {
	procsByPid = make(map[int32]*process.FilledProcess)
	for _, p := range procs {
		procsByPid[p.Pid] = p
	}
	return
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

func makeProcess(pid int32) *model.Process {
	return &model.Process{
		Pid: pid,
	}
}

func makeProcessFilled(pid int32, cmdline string) *process.FilledProcess {
	return &process.FilledProcess{
		Pid: pid,
		Cmdline:     strings.Split(cmdline, " "),
		MemInfo:     &process.MemoryInfoStat{},
		CtxSwitches: &process.NumCtxSwitchesStat{},
	}
}

func makeProcessStat(pid int32) *model.ProcessStat {
	return &model.ProcessStat{
		Pid: pid,
	}
}

// procMsgsVerification takes raw containers and processes and make sure the chunked messages have all data, and each chunk has the correct grouping
func procMsgsVerification(t *testing.T, msgs []model.MessageBody, rawContainers []*containers.Container, rawProcesses []*process.FilledProcess, maxSize int) {
	actualProcs := 0
	for _, msg := range msgs {
		payload := msg.(*model.CollectorProc)

		if len(payload.Containers) > 0 {
			// assume no blacklist involved
			assert.Equal(t, len(rawContainers), len(payload.Containers))

			procsByPid := make(map[int32]struct{}, len(payload.Processes))
			for _, p := range payload.Processes {
				procsByPid[p.Pid] = struct{}{}
			}

			// make sure all containerized processes are in the payload
			containeredProcs := 0
			for _, ctr := range rawContainers {
				for _, pid := range ctr.Pids {
					assert.Contains(t, procsByPid, pid)
					containeredProcs++
				}
			}
			assert.Equal(t, len(payload.Processes), containeredProcs)

			actualProcs += containeredProcs
		} else {
			assert.True(t, len(payload.Processes) <= maxSize)
			actualProcs += len(payload.Processes)
		}
	}
	assert.Equal(t, len(rawProcesses), actualProcs)
}

// TestRandomizeMessage generates some processes and containers, then do a deep dive on return messages and make sure the chunk logic holds
func TestRandomizeMessages(t *testing.T) {
	for i, tc := range []struct {
		testName                                string
		pCount, cCount, cProcs, maxSize, chunks int
	}{
		{
			testName: "no-containers",
			pCount:   100,
			cCount:   0,
			cProcs:   0,
			maxSize:  30,
			chunks:   4,
		},
		{
			testName: "no-processes",
			pCount:   0,
			cCount:   30,
			cProcs:   0,
			maxSize:  10,
			chunks:   1,
		},
		{
			testName: "container-process-mixed-1",
			pCount:   100,
			cCount:   30,
			cProcs:   60,
			maxSize:  30,
			chunks:   3,
		},
		{
			testName: "container-process-mixed-2",
			pCount:   100,
			cCount:   10,
			cProcs:   60,
			maxSize:  10,
			chunks:   5,
		},
		{
			testName: "container-process-mixed-3",
			pCount:   100,
			cCount:   100,
			cProcs:   100,
			maxSize:  10,
			chunks:   1,
		},
		{
			testName: "container-process-mixed-4",
			pCount:   100,
			cCount:   17,
			cProcs:   78,
			maxSize:  10,
			chunks:   4,
		},
	} {

		t.Run(tc.testName, func(t *testing.T) {
			procs, ctrs := procCtrGenerator(tc.pCount, tc.cCount, tc.cProcs)
			procsByPid := procsToHash(procs)

			lastRun := time.Now().Add(-5 * time.Second)
			syst1, syst2 := cpu.TimesStat{}, cpu.TimesStat{}
			cfg := config.NewDefaultAgentConfig()
			sysInfo := &model.SystemInfo{}
			lastCtrRates := util.ExtractContainerRateMetric(ctrs)

			cfg.MaxPerMessage = tc.maxSize
			processes := fmtProcesses(cfg, procsByPid, procsByPid, ctrs, syst2, syst1, lastRun)
			containers := fmtContainers(ctrs, lastCtrRates, lastRun)
			messages, totalProcs, totalContainers := createProcCtrMessages(processes, containers, cfg, sysInfo, int32(i))

			assert.Equal(t, totalProcs, tc.pCount)
			assert.Equal(t, totalContainers, tc.cCount)
			procMsgsVerification(t, messages, ctrs, procs, tc.maxSize)
		})
	}
}

// TestBasicProcessMessages tests basic cases for creating payloads by hard-coded scenarios
func TestBasicProcessMessages(t *testing.T) {
	p := []*process.FilledProcess{
		makeProcessFilled(1, "git clone google.com"),
		makeProcessFilled(2, "mine-bitcoins -all -x"),
		makeProcessFilled(3, "foo --version"),
		makeProcessFilled(4, "foo -bar -bim"),
		makeProcessFilled(5, "datadog-process-agent -ddconfig datadog.conf"),
	}
	c := []*containers.Container{
		makeContainer("foo"),
		makeContainer("bar"),
	}
	// first container runs pid1 and pid2
	c[0].Pids = []int32{1, 2}
	c[1].Pids = []int32{3}
	lastRun := time.Now().Add(-5 * time.Second)
	syst1, syst2 := cpu.TimesStat{}, cpu.TimesStat{}
	cfg := config.NewDefaultAgentConfig()
	sysInfo := &model.SystemInfo{}
	lastCtrRates := util.ExtractContainerRateMetric(c)

	for i, tc := range []struct {
		testName        string
		cur, last       map[int32]*process.FilledProcess
		containers      []*containers.Container
		maxSize         int
		blacklist       []string
		expectedChunks  int
		totalProcs      int
		totalContainers int
	}{
		{
			testName:        "no containers",
			cur:             map[int32]*process.FilledProcess{p[0].Pid: p[0], p[1].Pid: p[1], p[2].Pid: p[2]},
			last:            map[int32]*process.FilledProcess{p[0].Pid: p[0], p[1].Pid: p[1], p[2].Pid: p[2]},
			maxSize:         2,
			containers:      []*containers.Container{},
			blacklist:       []string{},
			expectedChunks:  2,
			totalProcs:      3,
			totalContainers: 0,
		},
		{
			testName:        "containered processes",
			cur:             map[int32]*process.FilledProcess{p[0].Pid: p[0], p[1].Pid: p[1], p[2].Pid: p[2]},
			last:            map[int32]*process.FilledProcess{p[0].Pid: p[0], p[1].Pid: p[1], p[2].Pid: p[2]},
			maxSize:         1,
			containers:      []*containers.Container{c[0]},
			blacklist:       []string{},
			expectedChunks:  2,
			totalProcs:      3,
			totalContainers: 1,
		},
		{
			testName:        "non-container processes chunked",
			cur:             map[int32]*process.FilledProcess{p[2].Pid: p[2], p[3].Pid: p[3], p[4].Pid: p[4]},
			last:            map[int32]*process.FilledProcess{p[2].Pid: p[2], p[3].Pid: p[3], p[4].Pid: p[4]},
			maxSize:         1,
			containers:      []*containers.Container{c[1]},
			blacklist:       []string{},
			expectedChunks:  3,
			totalProcs:      3,
			totalContainers: 1,
		},
		{
			testName:        "non-container processes not chunked",
			cur:             map[int32]*process.FilledProcess{p[2].Pid: p[2], p[3].Pid: p[3], p[4].Pid: p[4]},
			last:            map[int32]*process.FilledProcess{p[2].Pid: p[2], p[3].Pid: p[3], p[4].Pid: p[4]},
			maxSize:         3,
			containers:      []*containers.Container{c[1]},
			blacklist:       []string{},
			expectedChunks:  2,
			totalProcs:      3,
			totalContainers: 1,
		},
		{
			testName:        "no non-container processes",
			cur:             map[int32]*process.FilledProcess{p[0].Pid: p[0], p[1].Pid: p[1], p[2].Pid: p[2]},
			last:            map[int32]*process.FilledProcess{p[0].Pid: p[0], p[1].Pid: p[1], p[2].Pid: p[2]},
			maxSize:         1,
			containers:      []*containers.Container{c[0], c[1]},
			blacklist:       []string{},
			expectedChunks:  1,
			totalProcs:      3,
			totalContainers: 2,
		},
		{
			testName:        "all containered processes skipped",
			cur:             map[int32]*process.FilledProcess{p[0].Pid: p[0], p[1].Pid: p[1], p[2].Pid: p[2]},
			last:            map[int32]*process.FilledProcess{p[0].Pid: p[0], p[1].Pid: p[1], p[2].Pid: p[2]},
			maxSize:         2,
			containers:      []*containers.Container{c[1]},
			blacklist:       []string{"foo"},
			expectedChunks:  2,
			totalProcs:      2,
			totalContainers: 1,
		},
	} {
		t.Run(tc.testName, func(t *testing.T) {
			bl := make([]*regexp.Regexp, 0, len(tc.blacklist))
			for _, s := range tc.blacklist {
				bl = append(bl, regexp.MustCompile(s))
			}
			cfg.Blacklist = bl
			cfg.MaxPerMessage = tc.maxSize

			procs := fmtProcesses(cfg, tc.cur, tc.last, tc.containers, syst2, syst1, lastRun)
			containers := fmtContainers(tc.containers, lastCtrRates, lastRun)
			messages, totalProcs, totalContainers := createProcCtrMessages(procs, containers, cfg, sysInfo, int32(i))

			assert.Equal(t, tc.expectedChunks, len(messages))
			assert.Equal(t, tc.totalProcs, totalProcs)
			assert.Equal(t, tc.totalContainers, totalContainers)
		})
	}
}

func TestProcessChunking(t *testing.T) {
	cfg := config.NewDefaultAgentConfig()

	processes := []*model.Process{
		makeProcess(1),
		makeProcess(2),
		makeProcess(3),
		makeProcess(4),
		makeProcess(5),
		makeProcess(6),
		makeProcess(7),
		makeProcess(8),
		makeProcess(9),
		makeProcess(10),
		makeProcess(11),
		makeProcess(12),
		makeProcess(13),
		makeProcess(14),
		makeProcess(15),
		makeProcess(16),
		makeProcess(17),
		makeProcess(18),
		makeProcess(19),
		makeProcess(20),
		makeProcess(21),
	}
	processStats := []*model.ProcessStat{
		makeProcessStat(1),
		makeProcessStat(2),
		makeProcessStat(3),
		makeProcessStat(4),
		makeProcessStat(5),
		makeProcessStat(6),
		makeProcessStat(7),
		makeProcessStat(8),
		makeProcessStat(9),
		makeProcessStat(10),
		makeProcessStat(11),
		makeProcessStat(12),
		makeProcessStat(13),
		makeProcessStat(14),
		makeProcessStat(15),
		makeProcessStat(16),
		makeProcessStat(17),
		makeProcessStat(18),
		makeProcessStat(19),
		makeProcessStat(20),
		makeProcessStat(21),
	}

	for _, tc := range []struct {
		name           string
		maxSize        int
		expectedTotal  int
		expectedChunks int
	}{
		{
			name:           "Should create 7 chunks of 3 items and have a total of 21 items",
			maxSize:        3,
			expectedTotal:  21,
			expectedChunks: 7,
		},
		{
			name:           "Should create 1 chunk with 21 items and have a total of 21 items",
			maxSize:        21,
			expectedTotal:  21,
			expectedChunks: 1,
		},
	} {
		cfg.MaxPerMessage = tc.maxSize

		t.Run(tc.name, func(t *testing.T) {
			chunked := chunkProcesses(processes, tc.maxSize, make([][]*model.Process, 0, cfg.MaxPerMessage))
			assert.Len(t, chunked, tc.expectedChunks, "Test: [%s], expected chunks: %d, found chunks: %d", tc.name, tc.expectedChunks, len(chunked))
			total := 0
			for _, c := range chunked {
				total += len(c)
			}
			assert.Equal(t, total, tc.expectedTotal, "Test: [%s], expected total: %d, found total: %d", tc.name, tc.expectedTotal, total)

			chunkedStat := chunkProcessStats(processStats, tc.maxSize, make([][]*model.ProcessStat, 0, cfg.MaxPerMessage))
			assert.Len(t, chunkedStat, tc.expectedChunks, "Test: [%s], expected stats chunks: %d, found stats chunks: %d", tc.name, tc.expectedChunks, len(chunkedStat))
			total = 0
			for _, c := range chunkedStat {
				total += len(c)
			}
			assert.Equal(t, total, tc.expectedTotal, "Test: [%s], expected stats total: %d, found stats total: %d", tc.name, tc.expectedTotal, total)
		})
	}
}

func TestProcessBlacklisting(t *testing.T) {
	cfg := config.NewDefaultAgentConfig()

	for _, tc := range []struct {
		name      string
		blacklist []string
		process   *ProcessCommon
		expected  bool
	}{
		{
			name:      "Should filter process based on Blacklist",
			blacklist: []string{"process-name"},
			process: &ProcessCommon{
				Pid: 1,
				Command: &model.Command{
					Args:   []string{"process-name", "arguments"},
					Cwd:    "this/working/directory",
					Root:   "",
					OnDisk: false,
					Exe:    "path/to/executable",
				},
			},
			expected: false,
		},
		{
			name:      "Should filter process with empty arguments",
			blacklist: []string{},
			process: &ProcessCommon{
				Pid: 1,
				Command: &model.Command{
					Args:   []string{},
					Cwd:    "this/working/directory",
					Root:   "",
					OnDisk: false,
					Exe:    "path/to/executable",
				},
			},
			expected: false,
		},
		{
			name:      "Should filter unknown process without arguments or exe",
			blacklist: []string{},
			process: &ProcessCommon{
				Pid: 1,
				Command: &model.Command{
					Args:   []string{},
					Cwd:    "this/working/directory",
					Root:   "",
					OnDisk: false,
					Exe:    "",
				},
			},
			expected: false,
		},
		{
			name:      "Should not filter process with arguments that does not match a pattern in the blacklist",
			blacklist: []string{"non-matching-pattern"},
			process: &ProcessCommon{
				Pid: 1,
				Command: &model.Command{
					Args:   []string{"some", "args"},
					Cwd:    "this/working/directory",
					Root:   "",
					OnDisk: false,
					Exe:    "",
				},
			},
			expected: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bl := make([]*regexp.Regexp, 0, len(tc.blacklist))
			for _, s := range tc.blacklist {
				bl = append(bl, regexp.MustCompile(s))
			}
			cfg.Blacklist = bl

			filter := keepProcess(cfg)(tc.process)
			assert.Equal(t, tc.expected, filter, "Test: [%s], expected filter: %t, found filter: %t", tc.name, tc.expected, filter)
		})
	}
}

func TestProcessInclusions(t *testing.T) {
	cfg := config.NewDefaultAgentConfig()

	type Tags = []string
	for _, tc := range []struct {
		name                        string
		processes                   []*ProcessCommon
		amountTopCPUPercentageUsage int
		cpuPercentageUsageThreshold int
		amountTopIOReadUsage        int
		amountTopIOWriteUsage       int
		amountTopMemoryUsage        int
		memoryUsageThreshold        int
		expectedPidsTags            []struct {
			int
			Tags
		}
		totalCPUpercentage float32
		totalMemory        uint64
	}{
		{
			name: "Should return the correct top resource using processes",
			processes: []*ProcessCommon{
				{
					Pid:    1,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 20},
				},
				{
					Pid:    2,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 80},
				},
				{
					Pid:    3,
					CPU:    &model.CPUStat{TotalPct: 50},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    4,
					CPU:    &model.CPUStat{TotalPct: 80},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    5,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 10, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    6,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 50, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    7,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 50},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    8,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 80},
					Memory: &model.MemoryStat{Rss: 0},
				},
			},
			amountTopCPUPercentageUsage: 1,
			cpuPercentageUsageThreshold: 20,
			amountTopIOReadUsage:        1,
			amountTopIOWriteUsage:       1,
			amountTopMemoryUsage:        1,
			memoryUsageThreshold:        35,
			expectedPidsTags: []struct {
				int
				Tags
			}{
				{2, []string{TopMemory}},
				{4, []string{TopCPU}},
				{6, []string{TopIORead}},
				{8, []string{TopIOWrite}},
			},
			totalCPUpercentage: 25,
			totalMemory:        40,
		},
		{
			name: "Should independently return the process which consumed the most resources for each of the categories",
			processes: []*ProcessCommon{
				{
					Pid:    1,
					CPU:    &model.CPUStat{TotalPct: 100},
					IOStat: &model.IOStat{ReadRate: 100, WriteRate: 100},
					Memory: &model.MemoryStat{Rss: 100},
				},
				{
					Pid:    2,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 80},
				},
				{
					Pid:    3,
					CPU:    &model.CPUStat{TotalPct: 50},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    4,
					CPU:    &model.CPUStat{TotalPct: 80},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    5,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 10, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    6,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 50, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    7,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 50},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    8,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 80},
					Memory: &model.MemoryStat{Rss: 0},
				},
			},
			amountTopCPUPercentageUsage: 1,
			cpuPercentageUsageThreshold: 20,
			amountTopIOReadUsage:        1,
			amountTopIOWriteUsage:       1,
			amountTopMemoryUsage:        1,
			memoryUsageThreshold:        35,
			expectedPidsTags: []struct {
				int
				Tags
			}{{1, []string{TopMemory, TopCPU, TopIORead, TopIOWrite}}},
			totalCPUpercentage: 25,
			totalMemory:        40,
		},
		{
			name: "Should not return CPU / Memory top consuming processes when the thresholds are not exceeded",
			processes: []*ProcessCommon{
				{
					Pid:    1,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 20},
				},
				{
					Pid:    2,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 80},
				},
				{
					Pid:    3,
					CPU:    &model.CPUStat{TotalPct: 50},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    4,
					CPU:    &model.CPUStat{TotalPct: 80},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    5,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 10, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    6,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 50, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    7,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 50},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    8,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 80},
					Memory: &model.MemoryStat{Rss: 0},
				},
			},
			amountTopCPUPercentageUsage: 1,
			cpuPercentageUsageThreshold: 20,
			amountTopIOReadUsage:        1,
			amountTopIOWriteUsage:       1,
			amountTopMemoryUsage:        1,
			memoryUsageThreshold:        35,
			expectedPidsTags: []struct {
				int
				Tags
			}{
				{6, []string{TopIORead}},
				{8, []string{TopIOWrite}},
			},
			totalCPUpercentage: 10,
			totalMemory:        10,
		},
	} {
		cfg.AmountTopCPUPercentageUsage = tc.amountTopCPUPercentageUsage
		cfg.CPUPercentageUsageThreshold = tc.cpuPercentageUsageThreshold
		cfg.AmountTopIOReadUsage = tc.amountTopIOReadUsage
		cfg.AmountTopIOWriteUsage = tc.amountTopIOWriteUsage
		cfg.AmountTopMemoryUsage = tc.amountTopMemoryUsage
		cfg.MemoryUsageThreshold = tc.memoryUsageThreshold
		maxTopProcesses := cfg.AmountTopCPUPercentageUsage + cfg.AmountTopIOReadUsage + cfg.AmountTopIOWriteUsage + cfg.AmountTopMemoryUsage

		t.Run(tc.name, func(t *testing.T) {
			processInclusions := getProcessInclusions(tc.processes, cfg, tc.totalCPUpercentage, tc.totalMemory)
			assert.True(t, len(processInclusions) <= maxTopProcesses, fmt.Sprintf("Way too many top processes reported: %d > %d", len(processInclusions), maxTopProcesses))

			for _, proc := range processInclusions {
				pidTags := struct {
					int
					Tags
				}{int(proc.Pid), proc.Tags}
				assert.Contains(t, tc.expectedPidsTags, pidTags, fmt.Sprintf("Expected pids/tags: %v, found pid/tag: %v", tc.expectedPidsTags, pidTags))
			}
		})
	}
}

func TestProcessFormatting(t *testing.T) {
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
		//// expects all the processes not listed in the blacklist to be present as well as the top resource consuming
		//// processes regardless of whether they are blacklisted or not
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
		// only deal with non-container processes
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

	// Underflow on cur - prev
	assert.True(t, floatEquals(calculateRate(0, 1, prev), 0))
}

func TestFormatIO(t *testing.T) {
	fp := &process.FilledProcess{
		IOStat: &process.IOCountersStat{
			ReadCount:  6,
			WriteCount: 8,
			ReadBytes:  10,
			WriteBytes: 12,
		},
	}

	last := &process.IOCountersStat{
		ReadCount:  1,
		WriteCount: 2,
		ReadBytes:  3,
		WriteBytes: 4,
	}

	// fp.IoStat is nil
	assert.NotNil(t, formatIO(&process.FilledProcess{}, last, time.Now().Add(-2*time.Second)))

	// Elapsed time < 1s
	assert.NotNil(t, formatIO(fp, last, time.Now()))

	result := formatIO(fp, last, time.Now().Add(-1*time.Second))
	require.NotNil(t, result)

	assert.Equal(t, float32(5), result.ReadRate)
	assert.Equal(t, float32(6), result.WriteRate)
	assert.Equal(t, float32(7), result.ReadBytesRate)
	assert.Equal(t, float32(8), result.WriteBytesRate)

}

func floatEquals(a, b float32) bool {
	var e float32 = 0.00000001 // Difference less than some epsilon
	return a-b < e && b-a < e
}
