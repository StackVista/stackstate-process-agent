package checks

import (
	"fmt"
	"github.com/StackVista/stackstate-process-agent/model"
	"strings"
)

// endpointKey returns a EndpointId as scope:namespace:endpoint-ip-address:endpoint-port
func endpointKey(e *model.EndpointId) string {
	var values []string
	values = append(values, e.Scope)
	values = append(values, e.Namespace)

	if e.Endpoint != nil && e.Endpoint.Ip != nil {
		values = append(values, e.Endpoint.Ip.Address)
	}

	if e.Endpoint != nil {
		values = append(values, string(e.Endpoint.Port))
	}

	return strings.Join(values, ":")
}

// endpointKeyNoPort returns a EndpointId as scope:namespace:endpoint-ip-address
func endpointKeyNoPort(e *model.EndpointId) string {
	var values []string
	values = append(values, e.Scope)
	values = append(values, e.Namespace)

	if e.Endpoint != nil && e.Endpoint.Ip != nil {
		values = append(values, e.Endpoint.Ip.Address)
	}

	return strings.Join(values, ":")
}

// connectionRelationIdentifier returns an identification for the relation this connection may contribute to
func connectionRelationIdentifier(conn model.EnrichedConnection) string {

	// For directional relations, connections with the same source ip are grouped (port is ignored)
	// For non-directed relations ports are ignored on both sides
	switch conn.Direction {
	case model.ConnectionDirection_incoming:
		return fmt.Sprintf("in:%s:%s", endpointKey(conn.LocalEndpoint), endpointKeyNoPort(conn.RemoteEndpoint))
	case model.ConnectionDirection_outgoing:
		return fmt.Sprintf("out:%s:%s", endpointKeyNoPort(conn.LocalEndpoint), endpointKey(conn.RemoteEndpoint))
	default:
		return fmt.Sprintf("none:%s:%s", endpointKeyNoPort(conn.LocalEndpoint), endpointKeyNoPort(conn.RemoteEndpoint))
	}
}

/*
object ReceiverConnectionsApiRoute {
  def extractMessageConnection(hostName: String, message: CollectorMessage[CollectorConnections]): Seq[Connection] = {
    val payload = message.payload

    def toEndpoint(maybeAddr: Option[Addr], family: ConnectionFamily, namespace: Option[String]) =
      for {
        addr <- maybeAddr
        ip <- addr.ip
        port <- addr.port
      } yield makeEndpointId(hostName, ip, family.isv6, port, namespace)

    for {
      connection <- payload.connections
      // family default value 0 is significant so we expect it
      family = connection.getFamily
      pid <- connection.pid
      pidCreateTime <- connection.pidCreateTime
      localEndpoint <- toEndpoint(connection.laddr, family, connection.namespace)
      remoteEndpoint <- toEndpoint(connection.raddr, family, connection.namespace)
    } yield
      Connection(
        localProcessId = ProcessId(pid = pid, pidCreateTime = pidCreateTime),
        localEndpoint = localEndpoint,
        direction = getConnectionDirection(connection.getDirection),
        bytesSentPerSecond = connection.getBytesSentPerSecond.toDouble,
        bytesReceivedPerSecond = connection.getBytesReceivedPerSecond.toDouble,
        remoteEndpoint = remoteEndpoint,
        // cType default value 0 is significant so we expect it
        connectionType = if (connection.getType.equals(ProtoConnectionType.tcp)) ConnectionType.TCP else ConnectionType.UDP
      )
  }

  private def getConnectionDirection(direction: ConnectionDirection): Direction = direction match {
    case ConnectionDirection.outgoing => Direction.OUTGOING
    case ConnectionDirection.incoming => Direction.INCOMING
    case ConnectionDirection.none | ConnectionDirection.Unrecognized(_) => Direction.NONE
  }

	// check for localhost connection
	networkScanner := network.MakeLocalNetworkScanner()
	if networkScanner.ContainsIP(c.Local) && networkScanner.ContainsIP(c.Remote) {
		c.NetworkNamespace = namespace
	}

  def makeEndpointId(hostName: String, ip: String, isV6: Boolean, port: Int, namespace: Option[String]): EndpointId = {
    val inetAddress = InetAddress.getByName(ip)
    EndpointId(
      // In order to tell different pod-local ip addresses from each other,
      // treat each loopback address as local to the network namespace
      // Reference implementation: https://github.com/weaveworks/scope/blob/master/report/id.go#L40
      scope = if (inetAddress.isLoopbackAddress) Some(hostName) else None,
      namespace = namespace,
      endpoint = Endpoint(ip = Ip(address = inetAddress.getHostAddress, isIPv6 = isV6), port = port)
    )
  }
}
*/
