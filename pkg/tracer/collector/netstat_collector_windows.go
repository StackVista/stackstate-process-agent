package collector

import (
	"github.com/StackVista/stackstate-process-agent/pkg/tracer/common"
)

func (c NetstatCollector) GetTCPv4Connections() ([]*common.ConnectionStats, error) {
	return c.getNetstatConnections("tcp4", common.TCP, common.AF_INET)
}

func (c NetstatCollector) GetTCPv6Connections() ([]*common.ConnectionStats, error) {
	return c.getNetstatConnections("tcp6", common.TCP, common.AF_INET6)
}

func (c NetstatCollector) GetUDPv4Connections() ([]*common.ConnectionStats, error) {
	return c.getNetstatConnections("udp4", common.UDP, common.AF_INET)
}

func (c NetstatCollector) GetUDPv6Connections() ([]*common.ConnectionStats, error) {
	return c.getNetstatConnections("udp6", common.UDP, common.AF_INET6)
}

func (c NetstatCollector) getNetstatConnections(kind string, connectionType common.ConnectionType, connectionFamily common.ConnectionFamily) ([]*common.ConnectionStats, error) {
	var connectionStats = make([]*common.ConnectionStats, 0)

	conns, err := c.getConnections(kind)
	if err != nil {
		return nil, err
	}

	for _, conn := range conns {
		connection := c.toConnectionStats(conn, connectionType, connectionFamily)
		connectionStats = append(connectionStats, connection)
	}

	return connectionStats, nil
}

// Helper function to convert the netstat connection to a connection stats type
func (c NetstatCollector) toConnectionStats(conn winnetstat.NetStat, connectionType common.ConnectionType, connectionFamily common.ConnectionFamily) *common.ConnectionStats {
	connWithDirectionality := c.extractStateDirection(conn, connectionType)

	return &common.ConnectionStats{
		Pid:        uint32(conn.OwningPid),
		Type:       connectionType,
		Family:     connectionFamily,
		Local:      conn.LocalAddr,
		Remote:     conn.RemoteAddr,
		LocalPort:  conn.LocalPort,
		RemotePort: conn.RemotePort,
		Direction:  connWithDirectionality.Direction,
		State:      connWithDirectionality.State,
		SendBytes:  0,
		RecvBytes:  0,
	}
}

// Helper function to extract connection directionality from the netstat connection status
func (c NetstatCollector) extractStateDirection(conn winnetstat.NetStat, connectionType common.ConnectionType) NetstatConnection {

	switch connectionType {
	// directionality unknown
	case common.UDP:
		state, _ := c.stateToConnectionDirectionality(conn.State)
		return NetstatConnection{conn, state, common.UNKNOWN}
	default:
		state, direction := c.stateToConnectionDirectionality(conn.State)
		switch direction {
		case common.INCOMING:
			conn := NetstatConnection{conn, state, direction}
			c.listeningPorts[conn.LocalIdentity()] = &conn
			return conn
		default:
			conn := NetstatConnection{conn, state, direction}
			if _, exists := c.listeningPorts[conn.LocalIdentity()]; exists {
				conn.Direction = common.INCOMING
			}
			return conn
		}
	}
}

// Helper function to extract the State and Direction from the netstat connection status
func (c NetstatCollector) stateToConnectionDirectionality(state string) (State common.State, Direction common.Direction) {
	switch state {
	case "LISTEN":
		return common.ACTIVE, common.INCOMING

	case "ESTABLISHED":
		return common.ACTIVE, common.OUTGOING

	case "CLOSE_WAIT", "TIME_WAIT", "FIN_WAIT_1", "FIN_WAIT_2", "CLOSING", "LAST_ACK", "DELETE":
		return common.ACTIVE_CLOSED, common.UNKNOWN

	case "CLOSED":
		return common.CLOSED, common.UNKNOWN

	case "SYN_SENT":
		return common.INITIALIZING, common.OUTGOING

	case "SYN_RECEIVED":
		return common.INITIALIZING, common.INCOMING

	default:
		return common.ACTIVE, common.UNKNOWN
	}
}
