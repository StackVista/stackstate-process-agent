package checks

import (
	"sort"
	"time"

	"github.com/DataDog/gopsutil/cpu"
	"github.com/DataDog/gopsutil/process"
	"github.com/StackVista/stackstate-agent/pkg/util/containers"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/StackVista/stackstate-process-agent/util"
)

// RTProcess is a singleton RTProcessCheck.
var RTProcess = &RTProcessCheck{}

// RTProcessCheck collects numeric statistics about the live processes.
// The instance stores state between checks for calculation of rates and CPU.
type RTProcessCheck struct {
	sysInfo      *model.SystemInfo
	lastCPUTime  cpu.TimesStat
	lastProcs    map[int32]*process.FilledProcess
	lastCtrRates map[string]util.ContainerRateMetrics
	lastRun      time.Time
}

// Init initializes a new RTProcessCheck instance.
func (r *RTProcessCheck) Init(cfg *config.AgentConfig, info *model.SystemInfo) {
	r.sysInfo = info
}

// Name returns the name of the RTProcessCheck.
func (r *RTProcessCheck) Name() string { return "rtprocess" }

// Endpoint returns the endpoint where this check is submitted.
func (r *RTProcessCheck) Endpoint() string { return "/api/v1/collector" }

// RealTime indicates if this check only runs in real-time mode.
func (r *RTProcessCheck) RealTime() bool { return true }

// Run runs the RTProcessCheck to collect statistics about the running processes.
// On most POSIX systems these statistics are collected from procfs. The bulk
// of this collection is abstracted into the `gopsutil` library.
// Processes are split up into a chunks of at most 100 processes per message to
// limit the message size on intake.
// See agent.proto for the schema of the message and models used.
func (r *RTProcessCheck) Run(cfg *config.AgentConfig, groupID int32) ([]model.MessageBody, error) {
	cpuTimes, err := cpu.Times(false)
	if err != nil {
		return nil, err
	}
	procs, err := getAllProcesses(cfg)
	if err != nil {
		return nil, err
	}
	ctrList, _ := util.GetContainers()

	// End check early if this is our first run.
	if r.lastProcs == nil {
		r.lastCtrRates = util.ExtractContainerRateMetric(ctrList)
		r.lastProcs = procs
		r.lastCPUTime = cpuTimes[0]
		r.lastRun = time.Now()
		return nil, nil
	}

	chunkedStats := fmtProcessStats(cfg, procs, r.lastProcs,
		ctrList, cpuTimes[0], r.lastCPUTime, r.lastRun)
	groupSize := len(chunkedStats)
	chunkedCtrStats := fmtContainerStats(ctrList, r.lastCtrRates, r.lastRun, groupSize)
	messages := make([]model.MessageBody, 0, groupSize)
	for i := 0; i < groupSize; i++ {
		messages = append(messages, &model.CollectorRealTime{
			HostName:       cfg.HostName,
			Stats:          chunkedStats[i],
			ContainerStats: chunkedCtrStats[i],
			GroupId:        groupID,
			GroupSize:      int32(groupSize),
			NumCpus:        int32(len(r.sysInfo.Cpus)),
			TotalMemory:    r.sysInfo.TotalMemory,
		})
	}

	// Store the last state for comparison on the next run.
	// Note: not storing the filtered in case there are new processes that haven't had a chance to show up twice.
	r.lastRun = time.Now()
	r.lastProcs = procs
	r.lastCtrRates = util.ExtractContainerRateMetric(ctrList)
	r.lastCPUTime = cpuTimes[0]

	return messages, nil
}

// fmtProcessStats formats and chunks a slice of ProcessStat into chunks.
func fmtProcessStats(
	cfg *config.AgentConfig,
	procs, lastProcs map[int32]*process.FilledProcess,
	ctrList []*containers.Container,
	syst2, syst1 cpu.TimesStat,
	lastRun time.Time,
) [][]*model.ProcessStat {
	cidByPid := make(map[int32]string, len(ctrList))
	for _, c := range ctrList {
		for _, p := range c.Pids {
			cidByPid[p] = c.ID
		}
	}

	// Take all process and format them to the model.Process type
	formattedProcesses := make([]*model.ProcessStat, 0, cfg.MaxPerMessage)
	for _, fp := range procs {
		if _, ok := pidMissingInLastProcs(fp.Pid, lastProcs); ok {
			continue
		}

		formattedProcesses = append(formattedProcesses, &model.ProcessStat{
			Pid:                    fp.Pid,
			CreateTime:             fp.CreateTime,
			Memory:                 formatMemory(fp),
			Cpu:                    formatCPU(fp, fp.CpuTime, lastProcs[fp.Pid].CpuTime, syst2, syst1),
			Nice:                   fp.Nice,
			Threads:                fp.NumThreads,
			OpenFdCount:            fp.OpenFdCount,
			ProcessState:           model.ProcessState(model.ProcessState_value[fp.Status]),
			IoStat:                 formatIO(fp, lastProcs[fp.Pid].IOStat, lastRun),
			VoluntaryCtxSwitches:   uint64(fp.CtxSwitches.Voluntary),
			InvoluntaryCtxSwitches: uint64(fp.CtxSwitches.Involuntary),
			ContainerId:            cidByPid[fp.Pid],
		})
	}

	// Top Percentage Using Processes, insert into chuncked slice and strip from chunk slice
	sort.Slice(formattedProcesses, func(i, j int) bool {
		return formattedProcesses[i].Cpu.TotalPct > formattedProcesses[j].Cpu.TotalPct
	})
	var cpuSortedProcs, remainingProcesses []*model.ProcessStat
	if len(formattedProcesses) <= cfg.AmountTopCPUPercentageUsage {
		cpuSortedProcs, remainingProcesses = formattedProcesses, make([]*model.ProcessStat, 0, cfg.MaxPerMessage)
	} else {
		cpuSortedProcs, remainingProcesses = formattedProcesses[:cfg.AmountTopCPUPercentageUsage], formattedProcesses[cfg.AmountTopCPUPercentageUsage:]
	}

	// Top Read IO Using Processes, insert into chuncked slice and strip from chunk slice
	sort.Slice(remainingProcesses, func(i, j int) bool {
		return remainingProcesses[i].IoStat.ReadRate > remainingProcesses[j].IoStat.ReadRate
	})
	var ioReadSortedProcs []*model.ProcessStat
	if len(remainingProcesses) <= cfg.AmountTopIOUsage {
		ioReadSortedProcs, remainingProcesses = remainingProcesses, make([]*model.ProcessStat, 0, cfg.MaxPerMessage)
	} else {
		ioReadSortedProcs, remainingProcesses = remainingProcesses[:cfg.AmountTopIOUsage], remainingProcesses[cfg.AmountTopIOUsage:]
	}

	// Top Write IO Using Processes, insert into chuncked slice and strip from chunk slice
	sort.Slice(remainingProcesses, func(i, j int) bool {
		return remainingProcesses[i].IoStat.WriteRate > remainingProcesses[j].IoStat.WriteRate
	})
	var ioWriteSortedProcs []*model.ProcessStat
	if len(remainingProcesses) <= cfg.AmountTopIOUsage {
		ioWriteSortedProcs, remainingProcesses = remainingProcesses, make([]*model.ProcessStat, 0, cfg.MaxPerMessage)
	} else {
		ioWriteSortedProcs, remainingProcesses = remainingProcesses[:cfg.AmountTopIOUsage], remainingProcesses[cfg.AmountTopIOUsage:]
	}

	// Top Memory Using Processes, insert into chuncked slice and strip from chunk slice
	sort.Slice(remainingProcesses, func(i, j int) bool {
		return remainingProcesses[i].Memory.Rss > remainingProcesses[j].Memory.Rss
	})
	var memorySortedProcs []*model.ProcessStat
	if len(remainingProcesses) <= cfg.AmountTopMemoryUsage {
		memorySortedProcs, remainingProcesses = remainingProcesses, make([]*model.ProcessStat, 0, cfg.MaxPerMessage)
	} else {
		memorySortedProcs, remainingProcesses = remainingProcesses[:cfg.AmountTopMemoryUsage], remainingProcesses[cfg.AmountTopMemoryUsage:]
	}

	// Take the remainingProcesses of the process and strip all processes that should be skipped
	filteredProcessStats := remainingProcesses[:0]
	for _, proc := range remainingProcesses {
		if skipCompleteProcessStat(cfg, proc, lastProcs) {
			continue
		}

		filteredProcessStats = append(filteredProcessStats, proc)
	}

	processStatsToInclude := append(
		append(
			append(
				append(cpuSortedProcs, ioReadSortedProcs...),
				ioWriteSortedProcs...),
			memorySortedProcs...),
		filteredProcessStats...)

	return chunkProcessStats(processStatsToInclude, cfg.MaxPerMessage, make([][]*model.ProcessStat, 0))
}

func skipCompleteProcessStat(cfg *config.AgentConfig, fp *model.ProcessStat, lastProcs map[int32]*process.FilledProcess) bool {
	if filledProc, ok := pidMissingInLastProcs(fp.Pid, lastProcs); ok {
		return true
	} else {
		return skipProcess(cfg, filledProc, lastProcs)
	}
}

func chunkProcessStats(processStats []*model.ProcessStat, maxPerMessage int, chunked [][]*model.ProcessStat) [][]*model.ProcessStat {
	for maxPerMessage < len(processStats) {
		processStats, chunked = processStats[maxPerMessage:], append(chunked, processStats[0:maxPerMessage:maxPerMessage])
	}
	chunked = append(chunked, processStats)

	return chunked
}

func calculateRate(cur, prev uint64, before time.Time) float32 {
	now := time.Now()
	diff := now.Unix() - before.Unix()
	if before.IsZero() || diff <= 0 || prev == 0 {
		return 0
	}
	return float32(cur-prev) / float32(diff)
}
