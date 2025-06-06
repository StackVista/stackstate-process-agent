// Code generated by goderive DO NOT EDIT.

package checks

import (
	"bytes"
	"math"
	"sort"
	"strings"

	model "github.com/StackVista/stackstate-process-agent/model"
)

// deriveUniqueProcesses returns a list containing only the unique items from the input list.
// It does this by reusing the input list.
func deriveUniqueProcesses(list []*model.Process) []*model.Process {
	if len(list) == 0 {
		return nil
	}
	table := make(map[uint64][]int)
	u := 0
	for i := 0; i < len(list); i++ {
		contains := false
		hash := deriveHash(list[i])
		indexes := table[hash]
		for _, index := range indexes {
			if deriveEqual(list[index], list[i]) {
				contains = true
				break
			}
		}
		if contains {
			continue
		}
		if i != u {
			list[u] = list[i]
		}
		table[hash] = append(table[hash], u)
		u++
	}
	return list[:u]
}

// deriveUniqueProcessStats returns a list containing only the unique items from the input list.
// It does this by reusing the input list.
func deriveUniqueProcessStats(list []*model.ProcessStat) []*model.ProcessStat {
	if len(list) == 0 {
		return nil
	}
	table := make(map[uint64][]int)
	u := 0
	for i := 0; i < len(list); i++ {
		contains := false
		hash := deriveHash_(list[i])
		indexes := table[hash]
		for _, index := range indexes {
			if deriveEqual_(list[index], list[i]) {
				contains = true
				break
			}
		}
		if contains {
			continue
		}
		if i != u {
			list[u] = list[i]
		}
		table[hash] = append(table[hash], u)
		u++
	}
	return list[:u]
}

// deriveFilterProcesses returns a list of all items in the list that matches the predicate.
func deriveFilterProcesses(predicate func(*ProcessCommon) bool, list []*ProcessCommon) []*ProcessCommon {
	j := 0
	for i, elem := range list {
		if predicate(elem) {
			if i != j {
				list[j] = list[i]
			}
			j++
		}
	}
	return list[:j]
}

// deriveEqual returns whether this and that are equal.
func deriveEqual(this, that *model.Process) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Key == that.Key &&
			this.Pid == that.Pid &&
			deriveEqual_1(this.Host, that.Host) &&
			deriveEqual_2(this.Command, that.Command) &&
			deriveEqual_3(this.User, that.User) &&
			deriveEqual_4(this.Memory, that.Memory) &&
			deriveEqual_5(this.Cpu, that.Cpu) &&
			this.CreateTime == that.CreateTime &&
			deriveEqual_6(this.Container, that.Container) &&
			this.OpenFdCount == that.OpenFdCount &&
			this.State == that.State &&
			deriveEqual_7(this.IoStat, that.IoStat) &&
			this.ContainerId == that.ContainerId &&
			this.ContainerKey == that.ContainerKey &&
			this.VoluntaryCtxSwitches == that.VoluntaryCtxSwitches &&
			this.InvoluntaryCtxSwitches == that.InvoluntaryCtxSwitches &&
			bytes.Equal(this.ByteKey, that.ByteKey) &&
			bytes.Equal(this.ContainerByteKey, that.ContainerByteKey) &&
			deriveEqual_8(this.Tags, that.Tags)
}

// deriveEqual_ returns whether this and that are equal.
func deriveEqual_(this, that *model.ProcessStat) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Pid == that.Pid &&
			this.CreateTime == that.CreateTime &&
			deriveEqual_4(this.Memory, that.Memory) &&
			deriveEqual_5(this.Cpu, that.Cpu) &&
			this.Nice == that.Nice &&
			this.Threads == that.Threads &&
			this.OpenFdCount == that.OpenFdCount &&
			this.Key == that.Key &&
			this.ContainerId == that.ContainerId &&
			this.ContainerState == that.ContainerState &&
			this.ProcessState == that.ProcessState &&
			deriveEqual_7(this.IoStat, that.IoStat) &&
			this.ContainerHealth == that.ContainerHealth &&
			this.ContainerRbps == that.ContainerRbps &&
			this.ContainerWbps == that.ContainerWbps &&
			this.ContainerKey == that.ContainerKey &&
			this.ContainerNetRcvdPs == that.ContainerNetRcvdPs &&
			this.ContainerNetSentPs == that.ContainerNetSentPs &&
			this.ContainerNetRcvdBps == that.ContainerNetRcvdBps &&
			this.ContainerNetSentBps == that.ContainerNetSentBps &&
			this.VoluntaryCtxSwitches == that.VoluntaryCtxSwitches &&
			this.InvoluntaryCtxSwitches == that.InvoluntaryCtxSwitches &&
			bytes.Equal(this.ByteKey, that.ByteKey) &&
			bytes.Equal(this.ContainerByteKey, that.ContainerByteKey) &&
			deriveEqual_8(this.Tags, that.Tags)
}

// deriveSortProcesses sorts the slice inplace and also returns it.
func deriveSortProcesses(list []*model.Process) []*model.Process {
	sort.Slice(list, func(i, j int) bool { return deriveCompare(list[i], list[j]) < 0 })
	return list
}

// deriveSortProcessStats sorts the slice inplace and also returns it.
func deriveSortProcessStats(list []*model.ProcessStat) []*model.ProcessStat {
	sort.Slice(list, func(i, j int) bool { return deriveCompare_(list[i], list[j]) < 0 })
	return list
}

// deriveHash returns the hash of the object.
func deriveHash(object *model.Process) uint64 {
	if object == nil {
		return 0
	}
	h := uint64(17)
	h = 31*h + uint64(object.Key)
	h = 31*h + uint64(object.Pid)
	h = 31*h + deriveHash_1(object.Host)
	h = 31*h + deriveHash_2(object.Command)
	h = 31*h + deriveHash_3(object.User)
	h = 31*h + deriveHash_4(object.Memory)
	h = 31*h + deriveHash_5(object.Cpu)
	h = 31*h + uint64(object.CreateTime)
	h = 31*h + deriveHash_6(object.Container)
	h = 31*h + uint64(object.OpenFdCount)
	h = 31*h + uint64(object.State)
	h = 31*h + deriveHash_7(object.IoStat)
	h = 31*h + deriveHash_s(object.ContainerId)
	h = 31*h + uint64(object.ContainerKey)
	h = 31*h + object.VoluntaryCtxSwitches
	h = 31*h + object.InvoluntaryCtxSwitches
	h = 31*h + deriveHash_8(object.ByteKey)
	h = 31*h + deriveHash_8(object.ContainerByteKey)
	h = 31*h + deriveHash_9(object.Tags)
	return h
}

// deriveHash_ returns the hash of the object.
func deriveHash_(object *model.ProcessStat) uint64 {
	if object == nil {
		return 0
	}
	h := uint64(17)
	h = 31*h + uint64(object.Pid)
	h = 31*h + uint64(object.CreateTime)
	h = 31*h + deriveHash_4(object.Memory)
	h = 31*h + deriveHash_5(object.Cpu)
	h = 31*h + uint64(object.Nice)
	h = 31*h + uint64(object.Threads)
	h = 31*h + uint64(object.OpenFdCount)
	h = 31*h + uint64(object.Key)
	h = 31*h + deriveHash_s(object.ContainerId)
	h = 31*h + uint64(object.ContainerState)
	h = 31*h + uint64(object.ProcessState)
	h = 31*h + deriveHash_7(object.IoStat)
	h = 31*h + uint64(object.ContainerHealth)
	h = 31*h + uint64(math.Float32bits(object.ContainerRbps))
	h = 31*h + uint64(math.Float32bits(object.ContainerWbps))
	h = 31*h + uint64(object.ContainerKey)
	h = 31*h + uint64(math.Float32bits(object.ContainerNetRcvdPs))
	h = 31*h + uint64(math.Float32bits(object.ContainerNetSentPs))
	h = 31*h + uint64(math.Float32bits(object.ContainerNetRcvdBps))
	h = 31*h + uint64(math.Float32bits(object.ContainerNetSentBps))
	h = 31*h + object.VoluntaryCtxSwitches
	h = 31*h + object.InvoluntaryCtxSwitches
	h = 31*h + deriveHash_8(object.ByteKey)
	h = 31*h + deriveHash_8(object.ContainerByteKey)
	h = 31*h + deriveHash_9(object.Tags)
	return h
}

// deriveFmapCommonProcessToProcess returns a list where each element of the input list has been morphed by the input function.
func deriveFmapCommonProcessToProcess(f func(*ProcessCommon) *model.Process, list []*ProcessCommon) []*model.Process {
	out := make([]*model.Process, len(list))
	for i, elem := range list {
		out[i] = f(elem)
	}
	return out
}

// deriveFmapCommonProcessToProcessStat returns a list where each element of the input list has been morphed by the input function.
func deriveFmapCommonProcessToProcessStat(f func(*ProcessCommon) *model.ProcessStat, list []*ProcessCommon) []*model.ProcessStat {
	out := make([]*model.ProcessStat, len(list))
	for i, elem := range list {
		out[i] = f(elem)
	}
	return out
}

// deriveCompare returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare(this, that *model.Process) int {
	if this == nil {
		if that == nil {
			return 0
		}
		return -1
	}
	if that == nil {
		return 1
	}
	if c := deriveCompare_u(this.Key, that.Key); c != 0 {
		return c
	}
	if c := deriveCompare_i(this.Pid, that.Pid); c != 0 {
		return c
	}
	if c := deriveCompare_1(this.Host, that.Host); c != 0 {
		return c
	}
	if c := deriveCompare_2(this.Command, that.Command); c != 0 {
		return c
	}
	if c := deriveCompare_3(this.User, that.User); c != 0 {
		return c
	}
	if c := deriveCompare_4(this.Memory, that.Memory); c != 0 {
		return c
	}
	if c := deriveCompare_5(this.Cpu, that.Cpu); c != 0 {
		return c
	}
	if c := deriveCompare_in(this.CreateTime, that.CreateTime); c != 0 {
		return c
	}
	if c := deriveCompare_6(this.Container, that.Container); c != 0 {
		return c
	}
	if c := deriveCompare_i(this.OpenFdCount, that.OpenFdCount); c != 0 {
		return c
	}
	if c := deriveCompare_P(this.State, that.State); c != 0 {
		return c
	}
	if c := deriveCompare_7(this.IoStat, that.IoStat); c != 0 {
		return c
	}
	if c := strings.Compare(this.ContainerId, that.ContainerId); c != 0 {
		return c
	}
	if c := deriveCompare_u(this.ContainerKey, that.ContainerKey); c != 0 {
		return c
	}
	if c := deriveCompare_ui(this.VoluntaryCtxSwitches, that.VoluntaryCtxSwitches); c != 0 {
		return c
	}
	if c := deriveCompare_ui(this.InvoluntaryCtxSwitches, that.InvoluntaryCtxSwitches); c != 0 {
		return c
	}
	if c := bytes.Compare(this.ByteKey, that.ByteKey); c != 0 {
		return c
	}
	if c := bytes.Compare(this.ContainerByteKey, that.ContainerByteKey); c != 0 {
		return c
	}
	if c := deriveCompare_8(this.Tags, that.Tags); c != 0 {
		return c
	}
	return 0
}

// deriveCompare_ returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_(this, that *model.ProcessStat) int {
	if this == nil {
		if that == nil {
			return 0
		}
		return -1
	}
	if that == nil {
		return 1
	}
	if c := deriveCompare_i(this.Pid, that.Pid); c != 0 {
		return c
	}
	if c := deriveCompare_in(this.CreateTime, that.CreateTime); c != 0 {
		return c
	}
	if c := deriveCompare_4(this.Memory, that.Memory); c != 0 {
		return c
	}
	if c := deriveCompare_5(this.Cpu, that.Cpu); c != 0 {
		return c
	}
	if c := deriveCompare_i(this.Nice, that.Nice); c != 0 {
		return c
	}
	if c := deriveCompare_i(this.Threads, that.Threads); c != 0 {
		return c
	}
	if c := deriveCompare_i(this.OpenFdCount, that.OpenFdCount); c != 0 {
		return c
	}
	if c := deriveCompare_u(this.Key, that.Key); c != 0 {
		return c
	}
	if c := strings.Compare(this.ContainerId, that.ContainerId); c != 0 {
		return c
	}
	if c := deriveCompare_C(this.ContainerState, that.ContainerState); c != 0 {
		return c
	}
	if c := deriveCompare_P(this.ProcessState, that.ProcessState); c != 0 {
		return c
	}
	if c := deriveCompare_7(this.IoStat, that.IoStat); c != 0 {
		return c
	}
	if c := deriveCompare_Co(this.ContainerHealth, that.ContainerHealth); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.ContainerRbps, that.ContainerRbps); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.ContainerWbps, that.ContainerWbps); c != 0 {
		return c
	}
	if c := deriveCompare_u(this.ContainerKey, that.ContainerKey); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.ContainerNetRcvdPs, that.ContainerNetRcvdPs); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.ContainerNetSentPs, that.ContainerNetSentPs); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.ContainerNetRcvdBps, that.ContainerNetRcvdBps); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.ContainerNetSentBps, that.ContainerNetSentBps); c != 0 {
		return c
	}
	if c := deriveCompare_ui(this.VoluntaryCtxSwitches, that.VoluntaryCtxSwitches); c != 0 {
		return c
	}
	if c := deriveCompare_ui(this.InvoluntaryCtxSwitches, that.InvoluntaryCtxSwitches); c != 0 {
		return c
	}
	if c := bytes.Compare(this.ByteKey, that.ByteKey); c != 0 {
		return c
	}
	if c := bytes.Compare(this.ContainerByteKey, that.ContainerByteKey); c != 0 {
		return c
	}
	if c := deriveCompare_8(this.Tags, that.Tags); c != 0 {
		return c
	}
	return 0
}

// deriveEqual_1 returns whether this and that are equal.
func deriveEqual_1(this, that *model.Host) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Id == that.Id &&
			this.OrgId == that.OrgId &&
			this.Name == that.Name &&
			deriveEqual_9(this.Tags, that.Tags) &&
			deriveEqual_8(this.AllTags, that.AllTags) &&
			this.NumCpus == that.NumCpus &&
			this.TotalMemory == that.TotalMemory
}

// deriveEqual_2 returns whether this and that are equal.
func deriveEqual_2(this, that *model.Command) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			deriveEqual_8(this.Args, that.Args) &&
			this.Cwd == that.Cwd &&
			this.Root == that.Root &&
			this.OnDisk == that.OnDisk &&
			this.Ppid == that.Ppid &&
			this.Pgroup == that.Pgroup &&
			this.Exe == that.Exe
}

// deriveEqual_3 returns whether this and that are equal.
func deriveEqual_3(this, that *model.ProcessUser) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Name == that.Name &&
			this.Uid == that.Uid &&
			this.Gid == that.Gid &&
			this.Euid == that.Euid &&
			this.Egid == that.Egid &&
			this.Suid == that.Suid &&
			this.Sgid == that.Sgid
}

// deriveEqual_4 returns whether this and that are equal.
func deriveEqual_4(this, that *model.MemoryStat) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Rss == that.Rss &&
			this.Vms == that.Vms &&
			this.Swap == that.Swap &&
			this.Shared == that.Shared &&
			this.Text == that.Text &&
			this.Lib == that.Lib &&
			this.Data == that.Data &&
			this.Dirty == that.Dirty
}

// deriveEqual_5 returns whether this and that are equal.
func deriveEqual_5(this, that *model.CPUStat) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.LastCpu == that.LastCpu &&
			this.TotalPct == that.TotalPct &&
			this.UserPct == that.UserPct &&
			this.SystemPct == that.SystemPct &&
			this.NumThreads == that.NumThreads &&
			deriveEqual_10(this.Cpus, that.Cpus) &&
			this.Nice == that.Nice &&
			this.UserTime == that.UserTime &&
			this.SystemTime == that.SystemTime
}

// deriveEqual_6 returns whether this and that are equal.
func deriveEqual_6(this, that *model.Container) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Type == that.Type &&
			this.Id == that.Id &&
			this.Name == that.Name &&
			this.Image == that.Image &&
			this.CpuLimit == that.CpuLimit &&
			this.MemoryLimit == that.MemoryLimit &&
			this.State == that.State &&
			this.Health == that.Health &&
			this.Created == that.Created &&
			this.Rbps == that.Rbps &&
			this.Wbps == that.Wbps &&
			this.Key == that.Key &&
			this.NetRcvdPs == that.NetRcvdPs &&
			this.NetSentPs == that.NetSentPs &&
			this.NetRcvdBps == that.NetRcvdBps &&
			this.NetSentBps == that.NetSentBps &&
			this.UserPct == that.UserPct &&
			this.SystemPct == that.SystemPct &&
			this.TotalPct == that.TotalPct &&
			this.MemRss == that.MemRss &&
			this.MemCache == that.MemCache &&
			deriveEqual_1(this.Host, that.Host) &&
			this.Started == that.Started &&
			bytes.Equal(this.ByteKey, that.ByteKey) &&
			deriveEqual_8(this.Tags, that.Tags)
}

// deriveEqual_7 returns whether this and that are equal.
func deriveEqual_7(this, that *model.IOStat) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.ReadRate == that.ReadRate &&
			this.WriteRate == that.WriteRate &&
			this.ReadBytesRate == that.ReadBytesRate &&
			this.WriteBytesRate == that.WriteBytesRate
}

// deriveEqual_8 returns whether this and that are equal.
func deriveEqual_8(this, that []string) bool {
	if this == nil || that == nil {
		return this == nil && that == nil
	}
	if len(this) != len(that) {
		return false
	}
	for i := 0; i < len(this); i++ {
		if !(this[i] == that[i]) {
			return false
		}
	}
	return true
}

// deriveHash_1 returns the hash of the object.
func deriveHash_1(object *model.Host) uint64 {
	if object == nil {
		return 0
	}
	h := uint64(17)
	h = 31*h + uint64(object.Id)
	h = 31*h + uint64(object.OrgId)
	h = 31*h + deriveHash_s(object.Name)
	h = 31*h + deriveHash_10(object.Tags)
	h = 31*h + deriveHash_9(object.AllTags)
	h = 31*h + uint64(object.NumCpus)
	h = 31*h + uint64(object.TotalMemory)
	return h
}

// deriveHash_2 returns the hash of the object.
func deriveHash_2(object *model.Command) uint64 {
	if object == nil {
		return 0
	}
	h := uint64(17)
	h = 31*h + deriveHash_9(object.Args)
	h = 31*h + deriveHash_s(object.Cwd)
	h = 31*h + deriveHash_s(object.Root)
	h = 31*h + deriveHash_b(object.OnDisk)
	h = 31*h + uint64(object.Ppid)
	h = 31*h + uint64(object.Pgroup)
	h = 31*h + deriveHash_s(object.Exe)
	return h
}

// deriveHash_3 returns the hash of the object.
func deriveHash_3(object *model.ProcessUser) uint64 {
	if object == nil {
		return 0
	}
	h := uint64(17)
	h = 31*h + deriveHash_s(object.Name)
	h = 31*h + uint64(object.Uid)
	h = 31*h + uint64(object.Gid)
	h = 31*h + uint64(object.Euid)
	h = 31*h + uint64(object.Egid)
	h = 31*h + uint64(object.Suid)
	h = 31*h + uint64(object.Sgid)
	return h
}

// deriveHash_4 returns the hash of the object.
func deriveHash_4(object *model.MemoryStat) uint64 {
	if object == nil {
		return 0
	}
	h := uint64(17)
	h = 31*h + object.Rss
	h = 31*h + object.Vms
	h = 31*h + object.Swap
	h = 31*h + object.Shared
	h = 31*h + object.Text
	h = 31*h + object.Lib
	h = 31*h + object.Data
	h = 31*h + object.Dirty
	return h
}

// deriveHash_5 returns the hash of the object.
func deriveHash_5(object *model.CPUStat) uint64 {
	if object == nil {
		return 0
	}
	h := uint64(17)
	h = 31*h + deriveHash_s(object.LastCpu)
	h = 31*h + uint64(math.Float32bits(object.TotalPct))
	h = 31*h + uint64(math.Float32bits(object.UserPct))
	h = 31*h + uint64(math.Float32bits(object.SystemPct))
	h = 31*h + uint64(object.NumThreads)
	h = 31*h + deriveHash_11(object.Cpus)
	h = 31*h + uint64(object.Nice)
	h = 31*h + uint64(object.UserTime)
	h = 31*h + uint64(object.SystemTime)
	return h
}

// deriveHash_6 returns the hash of the object.
func deriveHash_6(object *model.Container) uint64 {
	if object == nil {
		return 0
	}
	h := uint64(17)
	h = 31*h + deriveHash_s(object.Type)
	h = 31*h + deriveHash_s(object.Id)
	h = 31*h + deriveHash_s(object.Name)
	h = 31*h + deriveHash_s(object.Image)
	h = 31*h + uint64(math.Float32bits(object.CpuLimit))
	h = 31*h + object.MemoryLimit
	h = 31*h + uint64(object.State)
	h = 31*h + uint64(object.Health)
	h = 31*h + uint64(object.Created)
	h = 31*h + uint64(math.Float32bits(object.Rbps))
	h = 31*h + uint64(math.Float32bits(object.Wbps))
	h = 31*h + uint64(object.Key)
	h = 31*h + uint64(math.Float32bits(object.NetRcvdPs))
	h = 31*h + uint64(math.Float32bits(object.NetSentPs))
	h = 31*h + uint64(math.Float32bits(object.NetRcvdBps))
	h = 31*h + uint64(math.Float32bits(object.NetSentBps))
	h = 31*h + uint64(math.Float32bits(object.UserPct))
	h = 31*h + uint64(math.Float32bits(object.SystemPct))
	h = 31*h + uint64(math.Float32bits(object.TotalPct))
	h = 31*h + object.MemRss
	h = 31*h + object.MemCache
	h = 31*h + deriveHash_1(object.Host)
	h = 31*h + uint64(object.Started)
	h = 31*h + deriveHash_8(object.ByteKey)
	h = 31*h + deriveHash_9(object.Tags)
	return h
}

// deriveHash_7 returns the hash of the object.
func deriveHash_7(object *model.IOStat) uint64 {
	if object == nil {
		return 0
	}
	h := uint64(17)
	h = 31*h + uint64(math.Float32bits(object.ReadRate))
	h = 31*h + uint64(math.Float32bits(object.WriteRate))
	h = 31*h + uint64(math.Float32bits(object.ReadBytesRate))
	h = 31*h + uint64(math.Float32bits(object.WriteBytesRate))
	return h
}

// deriveHash_s returns the hash of the object.
func deriveHash_s(object string) uint64 {
	var h uint64
	for _, c := range object {
		h = 31*h + uint64(c)
	}
	return h
}

// deriveHash_8 returns the hash of the object.
func deriveHash_8(object []byte) uint64 {
	if object == nil {
		return 0
	}
	h := uint64(17)
	for i := 0; i < len(object); i++ {
		h = 31*h + uint64(object[i])
	}
	return h
}

// deriveHash_9 returns the hash of the object.
func deriveHash_9(object []string) uint64 {
	if object == nil {
		return 0
	}
	h := uint64(17)
	for i := 0; i < len(object); i++ {
		h = 31*h + deriveHash_s(object[i])
	}
	return h
}

// deriveCompare_u returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_u(this, that uint32) int {
	if this != that {
		if this < that {
			return -1
		} else {
			return 1
		}
	}
	return 0
}

// deriveCompare_i returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_i(this, that int32) int {
	if this != that {
		if this < that {
			return -1
		} else {
			return 1
		}
	}
	return 0
}

// deriveCompare_1 returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_1(this, that *model.Host) int {
	if this == nil {
		if that == nil {
			return 0
		}
		return -1
	}
	if that == nil {
		return 1
	}
	if c := deriveCompare_i(this.Id, that.Id); c != 0 {
		return c
	}
	if c := deriveCompare_i(this.OrgId, that.OrgId); c != 0 {
		return c
	}
	if c := strings.Compare(this.Name, that.Name); c != 0 {
		return c
	}
	if c := deriveCompare_9(this.Tags, that.Tags); c != 0 {
		return c
	}
	if c := deriveCompare_8(this.AllTags, that.AllTags); c != 0 {
		return c
	}
	if c := deriveCompare_i(this.NumCpus, that.NumCpus); c != 0 {
		return c
	}
	if c := deriveCompare_in(this.TotalMemory, that.TotalMemory); c != 0 {
		return c
	}
	return 0
}

// deriveCompare_2 returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_2(this, that *model.Command) int {
	if this == nil {
		if that == nil {
			return 0
		}
		return -1
	}
	if that == nil {
		return 1
	}
	if c := deriveCompare_8(this.Args, that.Args); c != 0 {
		return c
	}
	if c := strings.Compare(this.Cwd, that.Cwd); c != 0 {
		return c
	}
	if c := strings.Compare(this.Root, that.Root); c != 0 {
		return c
	}
	if c := deriveCompare_b(this.OnDisk, that.OnDisk); c != 0 {
		return c
	}
	if c := deriveCompare_i(this.Ppid, that.Ppid); c != 0 {
		return c
	}
	if c := deriveCompare_i(this.Pgroup, that.Pgroup); c != 0 {
		return c
	}
	if c := strings.Compare(this.Exe, that.Exe); c != 0 {
		return c
	}
	return 0
}

// deriveCompare_3 returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_3(this, that *model.ProcessUser) int {
	if this == nil {
		if that == nil {
			return 0
		}
		return -1
	}
	if that == nil {
		return 1
	}
	if c := strings.Compare(this.Name, that.Name); c != 0 {
		return c
	}
	if c := deriveCompare_i(this.Uid, that.Uid); c != 0 {
		return c
	}
	if c := deriveCompare_i(this.Gid, that.Gid); c != 0 {
		return c
	}
	if c := deriveCompare_i(this.Euid, that.Euid); c != 0 {
		return c
	}
	if c := deriveCompare_i(this.Egid, that.Egid); c != 0 {
		return c
	}
	if c := deriveCompare_i(this.Suid, that.Suid); c != 0 {
		return c
	}
	if c := deriveCompare_i(this.Sgid, that.Sgid); c != 0 {
		return c
	}
	return 0
}

// deriveCompare_4 returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_4(this, that *model.MemoryStat) int {
	if this == nil {
		if that == nil {
			return 0
		}
		return -1
	}
	if that == nil {
		return 1
	}
	if c := deriveCompare_ui(this.Rss, that.Rss); c != 0 {
		return c
	}
	if c := deriveCompare_ui(this.Vms, that.Vms); c != 0 {
		return c
	}
	if c := deriveCompare_ui(this.Swap, that.Swap); c != 0 {
		return c
	}
	if c := deriveCompare_ui(this.Shared, that.Shared); c != 0 {
		return c
	}
	if c := deriveCompare_ui(this.Text, that.Text); c != 0 {
		return c
	}
	if c := deriveCompare_ui(this.Lib, that.Lib); c != 0 {
		return c
	}
	if c := deriveCompare_ui(this.Data, that.Data); c != 0 {
		return c
	}
	if c := deriveCompare_ui(this.Dirty, that.Dirty); c != 0 {
		return c
	}
	return 0
}

// deriveCompare_5 returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_5(this, that *model.CPUStat) int {
	if this == nil {
		if that == nil {
			return 0
		}
		return -1
	}
	if that == nil {
		return 1
	}
	if c := strings.Compare(this.LastCpu, that.LastCpu); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.TotalPct, that.TotalPct); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.UserPct, that.UserPct); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.SystemPct, that.SystemPct); c != 0 {
		return c
	}
	if c := deriveCompare_i(this.NumThreads, that.NumThreads); c != 0 {
		return c
	}
	if c := deriveCompare_10(this.Cpus, that.Cpus); c != 0 {
		return c
	}
	if c := deriveCompare_i(this.Nice, that.Nice); c != 0 {
		return c
	}
	if c := deriveCompare_in(this.UserTime, that.UserTime); c != 0 {
		return c
	}
	if c := deriveCompare_in(this.SystemTime, that.SystemTime); c != 0 {
		return c
	}
	return 0
}

// deriveCompare_in returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_in(this, that int64) int {
	if this != that {
		if this < that {
			return -1
		} else {
			return 1
		}
	}
	return 0
}

// deriveCompare_6 returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_6(this, that *model.Container) int {
	if this == nil {
		if that == nil {
			return 0
		}
		return -1
	}
	if that == nil {
		return 1
	}
	if c := strings.Compare(this.Type, that.Type); c != 0 {
		return c
	}
	if c := strings.Compare(this.Id, that.Id); c != 0 {
		return c
	}
	if c := strings.Compare(this.Name, that.Name); c != 0 {
		return c
	}
	if c := strings.Compare(this.Image, that.Image); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.CpuLimit, that.CpuLimit); c != 0 {
		return c
	}
	if c := deriveCompare_ui(this.MemoryLimit, that.MemoryLimit); c != 0 {
		return c
	}
	if c := deriveCompare_C(this.State, that.State); c != 0 {
		return c
	}
	if c := deriveCompare_Co(this.Health, that.Health); c != 0 {
		return c
	}
	if c := deriveCompare_in(this.Created, that.Created); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.Rbps, that.Rbps); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.Wbps, that.Wbps); c != 0 {
		return c
	}
	if c := deriveCompare_u(this.Key, that.Key); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.NetRcvdPs, that.NetRcvdPs); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.NetSentPs, that.NetSentPs); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.NetRcvdBps, that.NetRcvdBps); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.NetSentBps, that.NetSentBps); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.UserPct, that.UserPct); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.SystemPct, that.SystemPct); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.TotalPct, that.TotalPct); c != 0 {
		return c
	}
	if c := deriveCompare_ui(this.MemRss, that.MemRss); c != 0 {
		return c
	}
	if c := deriveCompare_ui(this.MemCache, that.MemCache); c != 0 {
		return c
	}
	if c := deriveCompare_1(this.Host, that.Host); c != 0 {
		return c
	}
	if c := deriveCompare_in(this.Started, that.Started); c != 0 {
		return c
	}
	if c := bytes.Compare(this.ByteKey, that.ByteKey); c != 0 {
		return c
	}
	if c := deriveCompare_8(this.Tags, that.Tags); c != 0 {
		return c
	}
	return 0
}

// deriveCompare_P returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_P(this, that model.ProcessState) int {
	if this != that {
		if this < that {
			return -1
		} else {
			return 1
		}
	}
	return 0
}

// deriveCompare_7 returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_7(this, that *model.IOStat) int {
	if this == nil {
		if that == nil {
			return 0
		}
		return -1
	}
	if that == nil {
		return 1
	}
	if c := deriveCompare_f(this.ReadRate, that.ReadRate); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.WriteRate, that.WriteRate); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.ReadBytesRate, that.ReadBytesRate); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.WriteBytesRate, that.WriteBytesRate); c != 0 {
		return c
	}
	return 0
}

// deriveCompare_ui returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_ui(this, that uint64) int {
	if this != that {
		if this < that {
			return -1
		} else {
			return 1
		}
	}
	return 0
}

// deriveCompare_8 returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_8(this, that []string) int {
	if this == nil {
		if that == nil {
			return 0
		}
		return -1
	}
	if that == nil {
		return 1
	}
	if len(this) != len(that) {
		if len(this) < len(that) {
			return -1
		}
		return 1
	}
	for i := 0; i < len(this); i++ {
		if c := strings.Compare(this[i], that[i]); c != 0 {
			return c
		}
	}
	return 0
}

// deriveCompare_C returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_C(this, that model.ContainerState) int {
	if this != that {
		if this < that {
			return -1
		} else {
			return 1
		}
	}
	return 0
}

// deriveCompare_Co returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_Co(this, that model.ContainerHealth) int {
	if this != that {
		if this < that {
			return -1
		} else {
			return 1
		}
	}
	return 0
}

// deriveCompare_f returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_f(this, that float32) int {
	if this != that {
		if this < that {
			return -1
		} else {
			return 1
		}
	}
	return 0
}

// deriveEqual_9 returns whether this and that are equal.
func deriveEqual_9(this, that []*model.HostTags) bool {
	if this == nil || that == nil {
		return this == nil && that == nil
	}
	if len(this) != len(that) {
		return false
	}
	for i := 0; i < len(this); i++ {
		if !(deriveEqual_11(this[i], that[i])) {
			return false
		}
	}
	return true
}

// deriveEqual_10 returns whether this and that are equal.
func deriveEqual_10(this, that []*model.SingleCPUStat) bool {
	if this == nil || that == nil {
		return this == nil && that == nil
	}
	if len(this) != len(that) {
		return false
	}
	for i := 0; i < len(this); i++ {
		if !(deriveEqual_12(this[i], that[i])) {
			return false
		}
	}
	return true
}

// deriveHash_10 returns the hash of the object.
func deriveHash_10(object []*model.HostTags) uint64 {
	if object == nil {
		return 0
	}
	h := uint64(17)
	for i := 0; i < len(object); i++ {
		h = 31*h + deriveHash_12(object[i])
	}
	return h
}

// deriveHash_b returns the hash of the object.
func deriveHash_b(object bool) uint64 {
	if object {
		return 1
	}
	return 0
}

// deriveHash_11 returns the hash of the object.
func deriveHash_11(object []*model.SingleCPUStat) uint64 {
	if object == nil {
		return 0
	}
	h := uint64(17)
	for i := 0; i < len(object); i++ {
		h = 31*h + deriveHash_13(object[i])
	}
	return h
}

// deriveCompare_9 returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_9(this, that []*model.HostTags) int {
	if this == nil {
		if that == nil {
			return 0
		}
		return -1
	}
	if that == nil {
		return 1
	}
	if len(this) != len(that) {
		if len(this) < len(that) {
			return -1
		}
		return 1
	}
	for i := 0; i < len(this); i++ {
		if c := deriveCompare_11(this[i], that[i]); c != 0 {
			return c
		}
	}
	return 0
}

// deriveCompare_b returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_b(this, that bool) int {
	if this == that {
		return 0
	}
	if that {
		return -1
	}
	return 1
}

// deriveCompare_10 returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_10(this, that []*model.SingleCPUStat) int {
	if this == nil {
		if that == nil {
			return 0
		}
		return -1
	}
	if that == nil {
		return 1
	}
	if len(this) != len(that) {
		if len(this) < len(that) {
			return -1
		}
		return 1
	}
	for i := 0; i < len(this); i++ {
		if c := deriveCompare_12(this[i], that[i]); c != 0 {
			return c
		}
	}
	return 0
}

// deriveEqual_11 returns whether this and that are equal.
func deriveEqual_11(this, that *model.HostTags) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.SourceType == that.SourceType &&
			deriveEqual_8(this.Tags, that.Tags)
}

// deriveEqual_12 returns whether this and that are equal.
func deriveEqual_12(this, that *model.SingleCPUStat) bool {
	return (this == nil && that == nil) ||
		this != nil && that != nil &&
			this.Name == that.Name &&
			this.TotalPct == that.TotalPct
}

// deriveHash_12 returns the hash of the object.
func deriveHash_12(object *model.HostTags) uint64 {
	if object == nil {
		return 0
	}
	h := uint64(17)
	h = 31*h + uint64(object.SourceType)
	h = 31*h + deriveHash_9(object.Tags)
	return h
}

// deriveHash_13 returns the hash of the object.
func deriveHash_13(object *model.SingleCPUStat) uint64 {
	if object == nil {
		return 0
	}
	h := uint64(17)
	h = 31*h + deriveHash_s(object.Name)
	h = 31*h + uint64(math.Float32bits(object.TotalPct))
	return h
}

// deriveCompare_11 returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_11(this, that *model.HostTags) int {
	if this == nil {
		if that == nil {
			return 0
		}
		return -1
	}
	if that == nil {
		return 1
	}
	if c := deriveCompare_u(this.SourceType, that.SourceType); c != 0 {
		return c
	}
	if c := deriveCompare_8(this.Tags, that.Tags); c != 0 {
		return c
	}
	return 0
}

// deriveCompare_12 returns:
//   - 0 if this and that are equal,
//   - -1 is this is smaller and
//   - +1 is this is bigger.
func deriveCompare_12(this, that *model.SingleCPUStat) int {
	if this == nil {
		if that == nil {
			return 0
		}
		return -1
	}
	if that == nil {
		return 1
	}
	if c := strings.Compare(this.Name, that.Name); c != 0 {
		return c
	}
	if c := deriveCompare_f(this.TotalPct, that.TotalPct); c != 0 {
		return c
	}
	return 0
}
