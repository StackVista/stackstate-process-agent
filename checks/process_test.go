package checks

import (
	"errors"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/util/containers"
	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/model"
	"github.com/DataDog/datadog-process-agent/util"
	"github.com/DataDog/gopsutil/cpu"
	"github.com/DataDog/gopsutil/process"
)

func procCtrGenerator(pCount int, cCount int, containeredProcs int) ([]*process.FilledProcess, []*containers.Container, error) {
	if (pCount < cCount) || (containeredProcs > pCount) {
		return nil, nil, errors.New("The process and container count specified is not valid")
	}
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

	return procs, ctrs, nil
}

func procsToHash(procs []*process.FilledProcess) (procsByPid map[int32]*process.FilledProcess) {
	procsByPid = make(map[int32]*process.FilledProcess)
	for _, p := range procs {
		procsByPid[p.Pid] = p
	}
	return
}

func makeProcess(pid int32, cmdline string) *process.FilledProcess {
	return &process.FilledProcess{
		Pid:         pid,
		Cmdline:     strings.Split(cmdline, " "),
		MemInfo:     &process.MemoryInfoStat{},
		CtxSwitches: &process.NumCtxSwitchesStat{},
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
			procs, ctrs, err := procCtrGenerator(tc.pCount, tc.cCount, tc.cProcs)
			procsByPid := procsToHash(procs)
			assert.NoError(t, err)

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
		makeProcess(1, "git clone google.com"),
		makeProcess(2, "mine-bitcoins -all -x"),
		makeProcess(3, "foo --version"),
		makeProcess(4, "foo -bar -bim"),
		makeProcess(5, "datadog-process-agent -ddconfig datadog.conf"),
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
			expectedChunks:  1,
			totalProcs:      2,
			totalContainers: 0,
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
	p := []*process.FilledProcess{
		makeProcess(1, "git clone google.com"),
		makeProcess(2, "mine-bitcoins -all -x"),
		makeProcess(3, "datadog-process-agent -ddconfig datadog.conf"),
		makeProcess(4, "foo -bar -bim"),
	}
	containers := []*containers.Container{}
	lastRun := time.Now().Add(-5 * time.Second)
	syst1, syst2 := cpu.TimesStat{}, cpu.TimesStat{}
	cfg := config.NewDefaultAgentConfig()

	for i, tc := range []struct {
		cur, last      []*process.FilledProcess
		maxSize        int
		blacklist      []string
		expectedTotal  int
		expectedChunks int
	}{
		{
			cur:            []*process.FilledProcess{p[0], p[1], p[2]},
			last:           []*process.FilledProcess{p[0], p[1], p[2]},
			maxSize:        1,
			blacklist:      []string{},
			expectedTotal:  3,
			expectedChunks: 3,
		},
		{
			cur:            []*process.FilledProcess{p[0], p[1], p[2]},
			last:           []*process.FilledProcess{p[0], p[2]},
			maxSize:        1,
			blacklist:      []string{},
			expectedTotal:  2,
			expectedChunks: 2,
		},
		{
			cur:            []*process.FilledProcess{p[0], p[1], p[2], p[3]},
			last:           []*process.FilledProcess{p[0], p[1], p[2], p[3]},
			maxSize:        10,
			blacklist:      []string{"git", "datadog"},
			expectedTotal:  2,
			expectedChunks: 1,
		},
		{
			cur:            []*process.FilledProcess{p[0], p[1], p[2], p[3]},
			last:           []*process.FilledProcess{p[0], p[1], p[2], p[3]},
			maxSize:        10,
			blacklist:      []string{"git", "datadog", "foo", "mine"},
			expectedTotal:  0,
			expectedChunks: 0,
		},
	} {
		bl := make([]*regexp.Regexp, 0, len(tc.blacklist))
		for _, s := range tc.blacklist {
			bl = append(bl, regexp.MustCompile(s))
		}
		cfg.Blacklist = bl
		cfg.MaxPerMessage = tc.maxSize

		cur := make(map[int32]*process.FilledProcess)
		for _, c := range tc.cur {
			cur[c.Pid] = c
		}
		last := make(map[int32]*process.FilledProcess)
		for _, c := range tc.last {
			last[c.Pid] = c
		}

		procs := fmtProcesses(cfg, cur, last, containers, syst2, syst1, lastRun)
		// only deal with non-container processes
		chunked := chunkProcesses(procs[emptyCtrID], cfg.MaxPerMessage)
		assert.Len(t, chunked, tc.expectedChunks, "len %d", i)
		total := 0
		for _, c := range chunked {
			total += len(c)
		}
		assert.Equal(t, tc.expectedTotal, total, "total test %d", i)

		chunkedStat := fmtProcessStats(cfg, cur, last, containers, syst2, syst1, lastRun)
		assert.Len(t, chunkedStat, tc.expectedChunks, "len stat %d", i)
		total = 0
		for _, c := range chunkedStat {
			total += len(c)
		}
		assert.Equal(t, tc.expectedTotal, total, "total stat test %d", i)
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
