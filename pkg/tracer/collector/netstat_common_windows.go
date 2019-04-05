package collector

import (
	"fmt"
	"github.com/StackVista/stackstate-process-agent/pkg/tracer/common"
)

type NetstatConnection struct {
	winnetstat.NetStat
	State     common.State
	Direction common.Direction
}

func (nc NetstatConnection) LocalIdentity() string {
	return fmt.Sprintf("[%s:%d:%d]", nc.LocalAddr, nc.LocalPort, nc.OwningPid)
}

// Connection collector interface. Can be mocked for testing.
type NetstatConnectionCollector interface {
	getConnections(kind string) ([]winnetstat.NetStat, error)
}

type NetstatCollector struct {
	NetstatConnectionCollector
	listeningPorts map[string]*NetstatConnection
}

// Default connection collector, that is used in the application.
type DefaultNetstatConnectionCollector struct{}

func (ctx DefaultNetstatConnectionCollector) getConnections(kind string) ([]winnetstat.NetStat, error) {
	return winnetstat.Connections(kind)
}

// MakeNetstatCollector to create the default Netstat Collector
func MakeNetstatCollector() *NetstatCollector {
	return &NetstatCollector{
		DefaultNetstatConnectionCollector{},
		make(map[string]*NetstatConnection),
	}
}
