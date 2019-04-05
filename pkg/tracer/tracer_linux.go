// +build linux_bpf

package tracer

import (
	"bytes"
	"github.com/StackVista/stackstate-process-agent/pkg/tracer/common"
	"github.com/StackVista/stackstate-process-agent/pkg/tracer/config"
	"github.com/StackVista/stackstate-process-agent/pkg/tracer/procspy"
	logger "github.com/cihub/seelog"
	"syscall"
	"unsafe"

	bpflib "github.com/iovisor/gobpf/elf"
)

/*
#include "../../tracer-ebpf/tcptracer-bpf.h"
*/
import "C"

type LinuxTracer struct {
	m      *bpflib.Module
	config *config.Config
	// In flight connections are the connections that already existed before the EBPF module was loaded.
	// These connections are stored with a key without direction, to make it possible to merge with undirected
	// metric stats
	inFlightTCP map[string]*common.ConnectionStats
}

func MakeTracer(config *config.Config) (Tracer, error) {
	m, err := loadBPFModule()
	if err != nil {
		return nil, err
	}

	err = m.Load(nil)
	if err != nil {
		return nil, err
	}

	// TODO: Only enable kprobes for traffic collection defined in config
	err = m.EnableKprobes(common.MaxActive)
	if err != nil {
		m.Close()
		if err != nil {
			return nil, logger.Error(err.Error())
		}
	}

	if err := initialize(m); err != nil {
		return nil, logger.Errorf("failed to init module: %s", err)
	}

	// TODO: Improve performance by detaching unnecessary kprobes, once offsets have been figured out in initialize()
	tracer := &LinuxTracer{m: m, config: config, inFlightTCP: make(map[string]*common.ConnectionStats)}

	// Get data from /proc AFTER ebpf has been initialized. This makes sure that we do not miss any
	// connections on the host. Some may be duplicate, but the mergin of inFlight end EBPF will sort this out
	if config.BackfillFromProc {
		err = tracer.getProcConnections()
		if err != nil {
			return nil, err
		}
	}

	return tracer, nil
}

// CheckTracerSupport returns whether or not the current kernel version supports tracer functionality
func CheckTracerSupport() (bool, error) {
	currentKernelCode, err := bpflib.CurrentKernelVersion()
	if err != nil {
		return false, err
	}

	if currentKernelCode < common.MinRequiredKernelCode {
		return false, logger.Errorf("incompatible linux version. at least %d required, got %d", common.MinRequiredKernelCode, currentKernelCode)
	}

	if err = ensureDebugFsMounted(); err != nil {
		return false, err
	}

	return true, nil
}

// We use debugfs interface to work with kprobes (kernel tracing) and we must ensure debugfs is mounted.
// On Amazon Linux due to a bug https://forums.aws.amazon.com/thread.jspa?messageID=753257
// debugfs is not automatically mounted and we try to mount ourselves
func ensureDebugFsMounted() error {
	err := syscall.Mount("debugfs", "/sys/kernel/debug", "debugfs", 0, "")
	if err != nil {
		// http://man7.org/linux/man-pages/man2/mount.2.html#ERRORS
		switch err {
		case syscall.EBUSY:
			logger.Info("debugfs already mounted")
		case syscall.EPERM:
			return logger.Error("no permissions to mount debugfs!")
		default:
			// http://www-numi.fnal.gov/offline_software/srt_public_context/WebDocs/Errors/unix_system_errors.html
			return logger.Errorf("debugfs mount error: %d - %s\n", err, err)
		}
	} else {
		logger.Info("debugfs successfully mounted")
	}
	return nil
}

func (t *LinuxTracer) Start() error {
	return nil
}

func (t *LinuxTracer) Stop() {
	logger.Info("Stopping linux network tracer")
	err := t.m.Close()
	if err != nil {
		logger.Error(err.Error())
	}
}

func (t *LinuxTracer) GetConnections() (*common.Connections, error) {
	err := t.updateInFlightTCPWithEBPF()
	if err != nil {
		return nil, err
	}

	tcpConns := t.getTcpConnectionsFromInFlight()

	udpConns, err := t.getEbpfUDPConnections()
	if err != nil {
		return nil, err
	}

	return &common.Connections{Conns: append(tcpConns, udpConns...)}, nil
}

// Linux Tracer internal functions
func (t *LinuxTracer) getProcConnections() error {
	procWalker := procspy.NewWalker(t.config.ProcRoot)
	scanner := procspy.NewSyncConnectionScanner(procWalker, t.config.ProcRoot, true)
	defer scanner.Stop()
	conns, err := scanner.Connections()

	if err != nil {
		return logger.Errorf("failed load existing connections: %s", err)
	}

	// No set in go, so we use a map... identify using connectionstats key from local port
	// Listening ports on specific interfaces
	listeningOnSpecificInterfaces := make(map[string]bool)
	listeningPortsOnAllInterfaces := make(map[uint16]bool)

	var connections []struct {
		common.ConnectionStats
		string
	}

	buffer := new(bytes.Buffer)

	// Collect the data and listening ports
	for conn := conns.Next(); conn != nil; conn = conns.Next() {
		connWithStats := connStatsFromProcSpy(conn)
		localKey, err := connWithStats.WithOnlyLocal().ByteKey(buffer)

		if conn.Proc.PID == 0 {
			continue
		}

		if err != nil {
			return logger.Errorf("failed to write to byte buffer: %s", err)
		}

		if conn.Listening {
			if conn.LocalAddress.IsUnspecified() {
				listeningPortsOnAllInterfaces[conn.LocalPort] = true
			} else {
				listeningOnSpecificInterfaces[string(localKey)] = true
			}
		} else {
			connections = append(connections, struct {
				common.ConnectionStats
				string
			}{connWithStats, string(localKey)})
		}
	}

	// Set the direction based on listening ports and add to inFlightTCP connections
	for _, connAndKey := range connections {
		conn := connAndKey.ConnectionStats
		if _, exists := listeningOnSpecificInterfaces[connAndKey.string]; exists {
			conn.Direction = common.INCOMING
		}

		if _, exists := listeningPortsOnAllInterfaces[conn.LocalPort]; exists {
			conn.Direction = common.INCOMING
		}

		// We drop the direction to enable merging with undirected metrics
		connKey, err := conn.WithUnknownDirection().ByteKey(buffer)

		if err != nil {
			return logger.Errorf("failed to write to byte buffer: %s", err)
		}

		t.addInFlight(string(connKey), conn)
	}

	return nil
}

func (t *LinuxTracer) getTcpConnectionsFromInFlight() []common.ConnectionStats {
	conns := make([]common.ConnectionStats, 0)

	for key, conn := range t.inFlightTCP {
		conns = append(conns, *conn)
		// Closed connection we only report once. After reporting,
		// they get removed from inFlight
		if conn.State == common.ACTIVE_CLOSED || conn.State == common.CLOSED {
			delete(t.inFlightTCP, key)
		}
	}

	return conns
}

// Get connection observations from EBPF and update inFlightTCP connections with that information
func (t *LinuxTracer) updateInFlightTCPWithEBPF() error {
	ebpf_conns, err := t.getEbpfTCPConnections()
	if err != nil {
		return err
	}

	buffer := new(bytes.Buffer)

	for _, conn := range ebpf_conns {
		// We drop the direction to enable merging with undirected metrics
		connKey, err := conn.WithUnknownDirection().ByteKey(buffer)

		if err != nil {
			return logger.Errorf("failed to write to byte buffer: %s", err)
		}

		// We are not interested in connections which are still initializing
		if conn.State == common.INITIALIZING {
			continue
		}

		if conn.Direction != common.UNKNOWN && conn.State != common.CLOSED {
			// If we already know the direction, we do not need previous in-flight connections and can just put this in, EBPF knows all
			t.addInFlight(string(connKey), conn)
		} else {
			// We had no direction, lets merge the info with what we learned from /proc
			if inFlight, exists := t.inFlightTCP[string(connKey)]; exists {
				inFlight.RecvBytes = conn.RecvBytes
				inFlight.SendBytes = conn.SendBytes
				inFlight.State = conn.State
				// If we observe just a close, we know it was active before (its in inFlight). So we make it ACTIVE_CLOSED
				if conn.State == common.CLOSED {
					inFlight.State = common.ACTIVE_CLOSED
				}
			}
		}
	}

	return nil
}

func (t *LinuxTracer) addInFlight(key string, conn common.ConnectionStats) {
	if len(t.inFlightTCP) >= t.config.MaxConnections {
		logger.Warnf("Exceeded maximum connections %d", t.config.MaxConnections)
		return
	}
	t.inFlightTCP[key] = &conn
}

func (t *LinuxTracer) getEbpfTCPConnections() ([]common.ConnectionStats, error) {
	conns := make([]common.ConnectionStats, 0)
	if t.config.CollectTCPConns {
		v4, err := t.getTCPv4Connections()
		if err != nil {
			return nil, err
		}
		v6, err := t.getTCPv6Connections()
		if err != nil {
			return nil, err
		}
		conns = append(conns, append(v4, v6...)...)
	}
	return conns, nil
}

func (t *LinuxTracer) getEbpfUDPConnections() ([]common.ConnectionStats, error) {
	conns := make([]common.ConnectionStats, 0)
	if t.config.CollectUDPConns {
		v4, err := t.getUDPv4Connections()
		if err != nil {
			return nil, err
		}
		v6, err := t.getUDPv6Connections()
		if err != nil {
			return nil, err
		}
		conns = append(conns, append(v4, v6...)...)
	}
	return conns, nil
}

func (t *LinuxTracer) getUDPv4Connections() ([]common.ConnectionStats, error) {
	mp, err := t.getMap(common.V4UDPMapName)
	if err != nil {
		return nil, err
	}

	tsMp, err := t.getMap(common.LatestTimestampMapName)
	if err != nil {
		return nil, err
	}

	var latestTime int64
	err = t.m.LookupElement(tsMp, unsafe.Pointer(&zero), unsafe.Pointer(&latestTime))
	if err != nil { // If we can't find latest timestamp, there probably hasn't been any UDP messages yet
		return nil, nil
	}

	// Iterate through all key-value pairs in map
	key, nextKey, stats := &ConnTupleV4{}, &ConnTupleV4{}, &ConnStatsWithTimestamp{}
	active := make([]common.ConnectionStats, 0)
	expired := make([]*ConnTupleV4, 0)
	for {
		hasNext, _ := t.m.LookupNextElement(mp, unsafe.Pointer(key), unsafe.Pointer(nextKey), unsafe.Pointer(stats))
		if !hasNext {
			break
		} else if stats.isExpired(latestTime, t.config.UDPConnTimeout.Nanoseconds()) {
			expired = append(expired, nextKey.copy())
		} else {
			active = append(active, connStatsFromUDPv4(nextKey, stats))
		}
		key = nextKey
	}

	// Remove expired entries
	for i := range expired {
		t.m.DeleteElement(mp, unsafe.Pointer(expired[i]))
	}
	return active, nil
}

func (t *LinuxTracer) getUDPv6Connections() ([]common.ConnectionStats, error) {
	mp, err := t.getMap(common.V6UDPMapName)
	if err != nil {
		return nil, err
	}

	tsMp, err := t.getMap(common.LatestTimestampMapName)
	if err != nil {
		return nil, err
	}

	var latestTime int64
	err = t.m.LookupElement(tsMp, unsafe.Pointer(&zero), unsafe.Pointer(&latestTime))
	if err != nil { // If we can't find latest timestamp, there probably hasn't been any UDP messages yet
		return nil, nil
	}

	// Iterate through all key-value pairs in map
	key, nextKey, stats := &ConnTupleV6{}, &ConnTupleV6{}, &ConnStatsWithTimestamp{}
	active := make([]common.ConnectionStats, 0)
	expired := make([]*ConnTupleV6, 0)
	for {
		hasNext, _ := t.m.LookupNextElement(mp, unsafe.Pointer(key), unsafe.Pointer(nextKey), unsafe.Pointer(stats))
		if !hasNext {
			break
		} else if stats.isExpired(latestTime, t.config.UDPConnTimeout.Nanoseconds()) {
			expired = append(expired, nextKey.copy())
		} else {
			active = append(active, connStatsFromUDPv6(nextKey, stats))
		}
		key = nextKey
	}

	// Remove expired entries
	for i := range expired {
		t.m.DeleteElement(mp, unsafe.Pointer(expired[i]))
	}
	return active, nil
}

func (t *LinuxTracer) getTCPv4Connections() ([]common.ConnectionStats, error) {
	mp, err := t.getMap(common.V4TCPMapName)
	if err != nil {
		return nil, err
	}

	// Iterate through all key-value pairs in map
	key, nextKey, val := &ConnTupleV4{}, &ConnTupleV4{}, &ConnStats{}
	conns := make([]common.ConnectionStats, 0)
	closed := make([]*ConnTupleV4, 0)
	for {
		hasNext, _ := t.m.LookupNextElement(mp, unsafe.Pointer(key), unsafe.Pointer(nextKey), unsafe.Pointer(val))
		if !hasNext {
			break
		} else {
			stats := connStatsFromTCPv4(nextKey, val)
			conns = append(conns, stats)
			if stats.State == common.ACTIVE_CLOSED || stats.State == common.CLOSED {
				closed = append(closed, nextKey.copy())
			}
			key = nextKey
		}
	}

	// Remove closed entries
	for i := range closed {
		t.m.DeleteElement(mp, unsafe.Pointer(closed[i]))
	}
	return conns, nil
}

func (t *LinuxTracer) getTCPv6Connections() ([]common.ConnectionStats, error) {
	mp, err := t.getMap(common.V6TCPMapName)
	if err != nil {
		return nil, err
	}

	// Iterate through all key-value pairs in map
	key, nextKey, val := &ConnTupleV6{}, &ConnTupleV6{}, &ConnStats{}
	conns := make([]common.ConnectionStats, 0)
	closed := make([]*ConnTupleV6, 0)
	for {
		hasNext, _ := t.m.LookupNextElement(mp, unsafe.Pointer(key), unsafe.Pointer(nextKey), unsafe.Pointer(val))
		if !hasNext {
			break
		} else {
			stats := connStatsFromTCPv6(nextKey, val)
			conns = append(conns, stats)
			if stats.State == common.ACTIVE_CLOSED || stats.State == common.CLOSED {
				closed = append(closed, nextKey.copy())
			}
			key = nextKey
		}
	}

	// Remove closed entries
	for i := range closed {
		t.m.DeleteElement(mp, unsafe.Pointer(closed[i]))
	}
	return conns, nil
}

func (t *LinuxTracer) getMap(mapName string) (*bpflib.Map, error) {
	mp := t.m.Map(mapName)
	if mp == nil {
		return nil, logger.Errorf("no map with name %s", mapName)
	}
	return mp, nil
}

func initialize(m *bpflib.Module) error {
	if err := guess(m); err != nil {
		return logger.Errorf("error guessing offsets: %v", err)
	}
	return nil
}

func loadBPFModule() (*bpflib.Module, error) {
	buf, err := Asset("tcptracer-ebpf.o")
	if err != nil {
		return nil, logger.Errorf("couldn't find asset: %s", err)
	}

	m := bpflib.NewModuleFromReader(bytes.NewReader(buf))
	if m == nil {
		return nil, logger.Errorf("BPF not supported")
	}
	return m, nil
}
