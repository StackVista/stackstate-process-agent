package checks

import (
	"github.com/DataDog/gopsutil/process"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/cihub/seelog"
	"sort"
	"time"
)

// ProcessCommon is the common process type used for sorting / process inclusions
type ProcessCommon struct {
	Pid     int32
	Command *model.Command
	Memory  *model.MemoryStat
	CPU     *model.CPUStat
	IoStat  *model.IOStat
}

// sorts the provided array with the specific sorting func and takes the top n process and return the remaining
func sortAndTakeN(processes []*ProcessCommon, sortingFunc func(processes []*ProcessCommon) func(i, j int) bool, n, defaultSize int) []*ProcessCommon {
	sort.Slice(processes, sortingFunc(processes))
	var topNProcesses []*ProcessCommon
	if len(processes) <= n {
		topNProcesses = processes
	} else {
		topNProcesses = processes[:n]
	}

	return topNProcesses
}

func getProcessInclusions(commonProcesses []*ProcessCommon, cfg *config.AgentConfig) []*ProcessCommon {
	cpuProcessChan := make(chan []*ProcessCommon)
	cpuProcesses := make([]*ProcessCommon, len(commonProcesses))
	copy(cpuProcesses, commonProcesses)

	ioReadProcessesChan := make(chan []*ProcessCommon)
	readProcesses := make([]*ProcessCommon, len(commonProcesses))
	copy(readProcesses, commonProcesses)

	ioWriteProcessesChan := make(chan []*ProcessCommon)
	writeProcesses := make([]*ProcessCommon, len(commonProcesses))
	copy(writeProcesses, commonProcesses)

	memoryProcessesChan := make(chan []*ProcessCommon)
	memoryProcesses := make([]*ProcessCommon, len(commonProcesses))
	copy(memoryProcesses, commonProcesses)

	// Top Percentage Using Processes, insert into chunked slice and strip from chunk slice
	go func() {
		percentageSort := func(processes []*ProcessCommon) func(i, j int) bool {
			sortingFunc := func(i, j int) bool {
				return processes[i].CPU.TotalPct > processes[j].CPU.TotalPct
			}

			return sortingFunc
		}
		cpuProcessChan <- sortAndTakeN(cpuProcesses, percentageSort, cfg.AmountTopCPUPercentageUsage, cfg.MaxPerMessage)
	}()

	// Top Read IO Using Processes, insert into chunked slice and strip from chunk slice
	go func() {
		readIOSort := func(processes []*ProcessCommon) func(i, j int) bool {
			sortingFunc := func(i, j int) bool {
				return processes[i].IoStat.ReadRate > processes[j].IoStat.ReadRate
			}

			return sortingFunc
		}
		ioReadProcessesChan <- sortAndTakeN(readProcesses, readIOSort, cfg.AmountTopIOReadUsage, cfg.MaxPerMessage)
	}()

	// Top Write IO Using Processes, insert into chunked slice and strip from chunk slice
	go func() {
		writeIOSort := func(processes []*ProcessCommon) func(i, j int) bool {
			sortingFunc := func(i, j int) bool {
				return processes[i].IoStat.WriteRate > processes[j].IoStat.WriteRate
			}

			return sortingFunc
		}
		ioWriteProcessesChan <- sortAndTakeN(writeProcesses, writeIOSort, cfg.AmountTopIOWriteUsage, cfg.MaxPerMessage)
	}()

	// Top Memory Using Processes, insert into chunked slice and strip from chunk slice
	go func() {
		memorySort := func(processes []*ProcessCommon) func(i, j int) bool {
			sortingFunc := func(i, j int) bool {
				return processes[i].Memory.Rss > processes[j].Memory.Rss
			}

			return sortingFunc
		}
		memoryProcessesChan <- sortAndTakeN(memoryProcesses, memorySort, cfg.AmountTopMemoryUsage, cfg.MaxPerMessage)
	}()

	return append(append(append(<-cpuProcessChan, <-ioReadProcessesChan...), <-ioWriteProcessesChan...), <-memoryProcessesChan...)
}

// Chunks process stats into predefined max per message size
func chunkProcessStats(processStats []*model.ProcessStat, maxPerMessage int, chunked [][]*model.ProcessStat) [][]*model.ProcessStat {
	if maxPerMessage < len(processStats) {
		seelog.Warnf("Amount of Processes: %d discovered exceeded MaxPerMessage: %d\n", len(processStats), maxPerMessage)
	}

	for maxPerMessage < len(processStats) {
		processStats, chunked = processStats[maxPerMessage:], append(chunked, processStats[0:maxPerMessage:maxPerMessage])
	}
	// checks the length of the processStats otherwise it appends an empty array to the chunked
	if len(processStats) == 0 {
		return chunked
	}
	return append(chunked, processStats)
}

// Chunks processes into predefined max per message size
func chunkProcesses(processes []*model.Process, maxPerMessage int, chunked [][]*model.Process) [][]*model.Process {
	if maxPerMessage < len(processes) {
		seelog.Warnf("Amount of Processes: %d discovered exceeded MaxPerMessage: %d\n", len(processes), maxPerMessage)
	}

	for maxPerMessage < len(processes) {
		processes, chunked = processes[maxPerMessage:], append(chunked, processes[0:maxPerMessage:maxPerMessage])
	}
	// checks the length of the processStats otherwise it appends an empty array to the chunked
	if len(processes) == 0 {
		return chunked
	}
	return append(chunked, processes)
}

func formatCommand(fp *process.FilledProcess) *model.Command {
	return &model.Command{
		Args:   fp.Cmdline,
		Cwd:    fp.Cwd,
		Root:   "",    // TODO
		OnDisk: false, // TODO
		Ppid:   fp.Ppid,
		Exe:    fp.Exe,
	}
}

func formatIO(fp *process.FilledProcess, lastIO *process.IOCountersStat, before time.Time) *model.IOStat {
	// This will be nill for Mac
	if fp.IOStat == nil {
		return &model.IOStat{}
	}

	diff := time.Now().Unix() - before.Unix()
	if before.IsZero() || diff <= 0 {
		return nil
	}
	// Reading 0 as a counter means the file could not be opened due to permissions. We distinguish this from a real 0 in rates.
	var readRate float32
	readRate = -1
	if fp.IOStat.ReadCount != 0 {
		readRate = calculateRate(fp.IOStat.ReadCount, lastIO.ReadCount, before)
	}
	var writeRate float32
	writeRate = -1
	if fp.IOStat.WriteCount != 0 {
		writeRate = calculateRate(fp.IOStat.WriteCount, lastIO.WriteCount, before)
	}
	var readBytesRate float32
	readBytesRate = -1
	if fp.IOStat.ReadBytes != 0 {
		readBytesRate = calculateRate(fp.IOStat.ReadBytes, lastIO.ReadBytes, before)
	}
	var writeBytesRate float32
	writeBytesRate = -1
	if fp.IOStat.WriteBytes != 0 {
		writeBytesRate = calculateRate(fp.IOStat.WriteBytes, lastIO.WriteBytes, before)
	}
	return &model.IOStat{
		ReadRate:       readRate,
		WriteRate:      writeRate,
		ReadBytesRate:  readBytesRate,
		WriteBytesRate: writeBytesRate,
	}
}

func calculateRate(cur, prev uint64, before time.Time) float32 {
	now := time.Now()
	diff := now.Unix() - before.Unix()
	if before.IsZero() || diff <= 0 || prev == 0 {
		return 0
	}
	return float32(cur-prev) / float32(diff)
}

func formatMemory(fp *process.FilledProcess) *model.MemoryStat {
	ms := &model.MemoryStat{
		Rss:  fp.MemInfo.RSS,
		Vms:  fp.MemInfo.VMS,
		Swap: fp.MemInfo.Swap,
	}

	if fp.MemInfoEx != nil {
		ms.Shared = fp.MemInfoEx.Shared
		ms.Text = fp.MemInfoEx.Text
		ms.Lib = fp.MemInfoEx.Lib
		ms.Data = fp.MemInfoEx.Data
		ms.Dirty = fp.MemInfoEx.Dirty
	}
	return ms
}

// checks if the process was in the previous collected processes
func pidMissingInLastProcs(pid int32, lastProcs map[int32]*process.FilledProcess) (*process.FilledProcess, bool) {
	lastProcess, ok := lastProcs[pid]

	if !ok {
		// Skipping any processes that didn't exist in the previous run.
		// This means short-lived processes (<2s) will never be captured.
		return nil, true
	}

	return lastProcess, false
}

// skipProcess will skip a given process if it's blacklisted or hasn't existed
// for multiple collections.
func isProcessBlacklisted(
	cfg *config.AgentConfig,
	cmdLine []string,
	exe string,
) bool {
	if len(cmdLine) == 0 {
		return true
	}

	if len(cmdLine) == 0 && len(exe) == 0 {
		return true
	}

	return config.IsBlacklisted(cmdLine, cfg.Blacklist)
}

func (p *ProcessCheck) createTimesforPIDs(pids []uint32) map[uint32]int64 {
	p.Lock()
	defer p.Unlock()

	createTimeForPID := make(map[uint32]int64)
	for _, pid := range pids {
		if p, ok := p.lastProcs[int32(pid)]; ok {
			createTimeForPID[pid] = p.CreateTime
		}
	}
	return createTimeForPID
}
