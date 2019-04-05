package collector

import (
	"github.com/StackVista/stackstate-process-agent/pkg/tracer/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func MockNetstatCollector() *NetstatCollector {
	collector := new(MockedNetstatCollector)
	collector.On("getConnections", mock.Anything).Return(Connections, nil)
	return &NetstatCollector{collector, make(map[string]*NetstatConnection)}
}

func TestExtractStateDirection(t *testing.T) {
	collector := MockNetstatCollector()

	state, direction := collector.stateToConnectionDirectionality("LISTEN")
	assert.Equal(t, state, common.ACTIVE)
	assert.Equal(t, direction, common.INCOMING)

	state, direction = collector.stateToConnectionDirectionality("ESTABLISHED")
	assert.Equal(t, state, common.ACTIVE)
	assert.Equal(t, direction, common.OUTGOING)

	state, direction = collector.stateToConnectionDirectionality("CLOSE_WAIT")
	assert.Equal(t, state, common.ACTIVE_CLOSED)
	assert.Equal(t, direction, common.UNKNOWN)

	state, direction = collector.stateToConnectionDirectionality("TIME_WAIT")
	assert.Equal(t, state, common.ACTIVE_CLOSED)
	assert.Equal(t, direction, common.UNKNOWN)

	state, direction = collector.stateToConnectionDirectionality("FIN_WAIT_1")
	assert.Equal(t, state, common.ACTIVE_CLOSED)
	assert.Equal(t, direction, common.UNKNOWN)

	state, direction = collector.stateToConnectionDirectionality("FIN_WAIT_2")
	assert.Equal(t, state, common.ACTIVE_CLOSED)
	assert.Equal(t, direction, common.UNKNOWN)

	state, direction = collector.stateToConnectionDirectionality("CLOSING")
	assert.Equal(t, state, common.ACTIVE_CLOSED)
	assert.Equal(t, direction, common.UNKNOWN)

	state, direction = collector.stateToConnectionDirectionality("LAST_ACK")
	assert.Equal(t, state, common.ACTIVE_CLOSED)
	assert.Equal(t, direction, common.UNKNOWN)

	state, direction = collector.stateToConnectionDirectionality("DELETE")
	assert.Equal(t, state, common.ACTIVE_CLOSED)
	assert.Equal(t, direction, common.UNKNOWN)

	state, direction = collector.stateToConnectionDirectionality("CLOSED")
	assert.Equal(t, state, common.CLOSED)
	assert.Equal(t, direction, common.UNKNOWN)

	state, direction = collector.stateToConnectionDirectionality("SYN_SENT")
	assert.Equal(t, state, common.INITIALIZING)
	assert.Equal(t, direction, common.OUTGOING)

	state, direction = collector.stateToConnectionDirectionality("SYN_RECEIVED")
	assert.Equal(t, state, common.INITIALIZING)
	assert.Equal(t, direction, common.INCOMING)

}

func TestNetstatToConnectionStats(t *testing.T) {
	collector := MockNetstatCollector()

	// Test incoming TCP connection
	initialConn := winnetstat.NetStat{
		LocalAddr:  "127.0.0.1",
		LocalPort:  8080,
		RemoteAddr: "192.168.2.111",
		RemotePort: 8080,
		OwningPid:  10,
		State:      "LISTEN",
	}

	actualConn := collector.toConnectionStats(initialConn, common.TCP, common.AF_INET)

	expectedConn := common.ConnectionStats{
		Pid:        uint32(initialConn.OwningPid),
		Type:       common.TCP,
		Family:     common.AF_INET,
		Local:      initialConn.LocalAddr,
		Remote:     initialConn.RemoteAddr,
		LocalPort:  initialConn.LocalPort,
		RemotePort: initialConn.RemotePort,
		Direction:  common.INCOMING,
		State:      common.ACTIVE,
		SendBytes:  0,
		RecvBytes:  0,
	}

	assert.Equal(t, *actualConn, expectedConn)

	// Test outgoing TCP connection
	initialConn = winnetstat.NetStat{
		LocalAddr:  "192.168.2.30",
		LocalPort:  11252,
		RemoteAddr: "192.168.2.31",
		RemotePort: 8081,
		OwningPid:  13,
		State:      "ESTABLISHED",
	}

	actualConn = collector.toConnectionStats(initialConn, common.TCP, common.AF_INET)

	expectedConn = common.ConnectionStats{
		Pid:        uint32(initialConn.OwningPid),
		Type:       common.TCP,
		Family:     common.AF_INET,
		Local:      initialConn.LocalAddr,
		Remote:     initialConn.RemoteAddr,
		LocalPort:  initialConn.LocalPort,
		RemotePort: initialConn.RemotePort,
		Direction:  common.OUTGOING,
		State:      common.ACTIVE,
		SendBytes:  0,
		RecvBytes:  0,
	}

	assert.Equal(t, *actualConn, expectedConn)

	// Test incoming TCPv6 connection
	initialConn = winnetstat.NetStat{
		LocalAddr:  "127.0.0.1",
		LocalPort:  8080,
		RemoteAddr: "192.168.2.111",
		RemotePort: 8080,
		OwningPid:  10,
		State:      "LISTEN",
	}

	actualConn = collector.toConnectionStats(initialConn, common.TCP, common.AF_INET6)

	expectedConn = common.ConnectionStats{
		Pid:        uint32(initialConn.OwningPid),
		Type:       common.TCP,
		Family:     common.AF_INET6,
		Local:      initialConn.LocalAddr,
		Remote:     initialConn.RemoteAddr,
		LocalPort:  initialConn.LocalPort,
		RemotePort: initialConn.RemotePort,
		Direction:  common.INCOMING,
		State:      common.ACTIVE,
		SendBytes:  0,
		RecvBytes:  0,
	}

	assert.Equal(t, *actualConn, expectedConn)

	// Test outgoing TCPv6 connection
	initialConn = winnetstat.NetStat{
		LocalAddr:  "192.168.2.30",
		LocalPort:  11252,
		RemoteAddr: "192.168.2.31",
		RemotePort: 8081,
		OwningPid:  13,
		State:      "ESTABLISHED",
	}

	actualConn = collector.toConnectionStats(initialConn, common.TCP, common.AF_INET6)

	expectedConn = common.ConnectionStats{
		Pid:        uint32(initialConn.OwningPid),
		Type:       common.TCP,
		Family:     common.AF_INET6,
		Local:      initialConn.LocalAddr,
		Remote:     initialConn.RemoteAddr,
		LocalPort:  initialConn.LocalPort,
		RemotePort: initialConn.RemotePort,
		Direction:  common.OUTGOING,
		State:      common.ACTIVE,
		SendBytes:  0,
		RecvBytes:  0,
	}

	assert.Equal(t, *actualConn, expectedConn)

	// Test UDP v4 connection
	initialConn = winnetstat.NetStat{
		LocalAddr:  "127.0.0.1",
		LocalPort:  8080,
		RemoteAddr: "192.168.2.111",
		RemotePort: 8080,
		OwningPid:  10,
		State:      "LISTEN",
	}

	actualConn = collector.toConnectionStats(initialConn, common.UDP, common.AF_INET)

	expectedConn = common.ConnectionStats{
		Pid:        uint32(initialConn.OwningPid),
		Type:       common.UDP,
		Family:     common.AF_INET,
		Local:      initialConn.LocalAddr,
		Remote:     initialConn.RemoteAddr,
		LocalPort:  initialConn.LocalPort,
		RemotePort: initialConn.RemotePort,
		Direction:  common.UNKNOWN,
		State:      common.ACTIVE,
		SendBytes:  0,
		RecvBytes:  0,
	}

	assert.Equal(t, *actualConn, expectedConn)

	// Test UDP v6 connection
	initialConn = winnetstat.NetStat{
		LocalAddr:  "192.168.2.32",
		LocalPort:  11256,
		RemoteAddr: "192.168.2.33",
		RemotePort: 8082,
		OwningPid:  14,
		State:      "ESTABLISHED",
	}

	actualConn = collector.toConnectionStats(initialConn, common.UDP, common.AF_INET6)

	expectedConn = common.ConnectionStats{
		Pid:        uint32(initialConn.OwningPid),
		Type:       common.UDP,
		Family:     common.AF_INET6,
		Local:      initialConn.LocalAddr,
		Remote:     initialConn.RemoteAddr,
		LocalPort:  initialConn.LocalPort,
		RemotePort: initialConn.RemotePort,
		Direction:  common.UNKNOWN,
		State:      common.ACTIVE,
		SendBytes:  0,
		RecvBytes:  0,
	}

	assert.Equal(t, *actualConn, expectedConn)

}

func TestGetConnections(t *testing.T) {
	collector := MockNetstatCollector()

	conns, err := collector.GetTCPv4Connections()
	if err != nil {
		t.Fatal(err)
	}
	for _, conn := range conns {
		initialConn := *conn

		expectedConn := common.ConnectionStats{
			Pid:        initialConn.Pid,
			Type:       common.TCP,
			Family:     common.AF_INET,
			Local:      initialConn.Local,
			Remote:     initialConn.Remote,
			LocalPort:  initialConn.LocalPort,
			RemotePort: initialConn.RemotePort,
			Direction:  initialConn.Direction,
			State:      initialConn.State,
			SendBytes:  0,
			RecvBytes:  0,
		}

		assert.Equal(t, initialConn, expectedConn)
	}

	conns, err = collector.GetTCPv6Connections()
	if err != nil {
		t.Fatal(err)
	}
	for _, conn := range conns {
		initialConn := *conn

		expectedConn := common.ConnectionStats{
			Pid:        initialConn.Pid,
			Type:       common.TCP,
			Family:     common.AF_INET6,
			Local:      initialConn.Local,
			Remote:     initialConn.Remote,
			LocalPort:  initialConn.LocalPort,
			RemotePort: initialConn.RemotePort,
			Direction:  initialConn.Direction,
			State:      initialConn.State,
			SendBytes:  0,
			RecvBytes:  0,
		}

		assert.Equal(t, initialConn, expectedConn)
	}

	conns, err = collector.GetUDPv4Connections()
	if err != nil {
		t.Fatal(err)
	}
	for _, conn := range conns {
		initialConn := *conn

		expectedConn := common.ConnectionStats{
			Pid:        initialConn.Pid,
			Type:       common.UDP,
			Family:     common.AF_INET,
			Local:      initialConn.Local,
			Remote:     initialConn.Remote,
			LocalPort:  initialConn.LocalPort,
			RemotePort: initialConn.RemotePort,
			Direction:  initialConn.Direction,
			State:      initialConn.State,
			SendBytes:  0,
			RecvBytes:  0,
		}

		assert.Equal(t, initialConn, expectedConn)
	}

	conns, err = collector.GetUDPv6Connections()
	if err != nil {
		t.Fatal(err)
	}
	for _, conn := range conns {
		initialConn := *conn

		expectedConn := common.ConnectionStats{
			Pid:        initialConn.Pid,
			Type:       common.UDP,
			Family:     common.AF_INET6,
			Local:      initialConn.Local,
			Remote:     initialConn.Remote,
			LocalPort:  initialConn.LocalPort,
			RemotePort: initialConn.RemotePort,
			Direction:  initialConn.Direction,
			State:      initialConn.State,
			SendBytes:  0,
			RecvBytes:  0,
		}

		assert.Equal(t, initialConn, expectedConn)
	}

}

type MockedNetstatCollector struct {
	mock.Mock
}

func (mock *MockedNetstatCollector) getConnections(kind string) ([]winnetstat.NetStat, error) {
	args := mock.Called(kind)
	return args.Get(0).([]winnetstat.NetStat), args.Error(1)
}

var Connections = []winnetstat.NetStat{
	winnetstat.NetStat{
		LocalAddr:  "127.0.0.1",
		LocalPort:  8080,
		RemoteAddr: "192.168.2.111",
		RemotePort: 8080,
		OwningPid:  10,
		State:      "LISTEN",
	},
	winnetstat.NetStat{
		LocalAddr:  "127.0.0.1",
		LocalPort:  5050,
		RemoteAddr: "192.168.2.25",
		RemotePort: 0,
		OwningPid:  11,
		State:      "LISTEN",
	},
	winnetstat.NetStat{
		LocalAddr:  "192.168.2.20",
		LocalPort:  7070,
		RemoteAddr: "192.168.2.100",
		RemotePort: 11253,
		OwningPid:  12,
		State:      "LISTEN",
	},
	winnetstat.NetStat{
		LocalAddr:  "192.168.2.30",
		LocalPort:  11252,
		RemoteAddr: "192.168.2.31",
		RemotePort: 8081,
		OwningPid:  13,
		State:      "ESTABLISHED",
	},
	winnetstat.NetStat{
		LocalAddr:  "192.168.2.32",
		LocalPort:  11256,
		RemoteAddr: "192.168.2.33",
		RemotePort: 8082,
		OwningPid:  14,
		State:      "ESTABLISHED",
	},
	winnetstat.NetStat{
		LocalAddr:  "192.168.2.40",
		LocalPort:  9000,
		RemoteAddr: "192.168.2.50",
		RemotePort: 8086,
		OwningPid:  15,
		State:      "CLOSE_WAIT",
	},
}
