package checks

import (
	"fmt"
	"github.com/DataDog/datadog-agent/comp/core/telemetry"
	"github.com/DataDog/datadog-agent/comp/core/telemetry/telemetryimpl"
	"github.com/DataDog/datadog-agent/pkg/network"
	tracerConfig "github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/tracer"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"

	log "github.com/cihub/seelog"
	"strconv"
	"strings"
	"time"
)

// CreateNetworkRelationIdentifier returns an identification for the relation this connection may contribute to
// this is a approximation of how StackState identifies multiple connections to belong to the same
// relation. Because at this point we do not have any means to correlate, sometimes the identification is
// 'widened', meaning that the relation is made less specific to avoid dropping data that we wanted to include.
func CreateNetworkRelationIdentifier(cfg *config.AgentConfig, conn network.ConnectionStats) string {
	isV6 := conn.Family == network.AFINET6
	localEndpoint := makeEndpointID(cfg, conn.NetNS, conn.Source, isV6, conn.SPort)
	remoteEndpoint := makeEndpointID(cfg, conn.NetNS, conn.Dest, isV6, conn.DPort)
	return createRelationIdentifier(localEndpoint, remoteEndpoint, conn.Direction)
}

type ip struct {
	Address string
	IsIPv6  bool
}

type endpoint struct {
	ip   *ip
	Port uint16
}

type endpointID struct {
	Scope    string
	Endpoint *endpoint
}

// endpointKey returns a endpointID as scope:endpoint-ip-address:endpoint-port
func endpointKey(e *endpointID) string {
	var values []string
	values = append(values, e.Scope)

	if e.Endpoint != nil && e.Endpoint.ip != nil {
		values = append(values, e.Endpoint.ip.Address)
	}

	if e.Endpoint != nil {
		values = append(values, strconv.Itoa(int(e.Endpoint.Port)))
	}

	return strings.Join(values, ":")
}

// endpointKeyNoPort returns a endpointID as scope:endpoint-ip-address
func endpointKeyNoPort(e *endpointID) string {
	var values []string
	values = append(values, e.Scope)

	if e.Endpoint != nil && e.Endpoint.ip != nil {
		values = append(values, e.Endpoint.ip.Address)
	}

	return strings.Join(values, ":")
}

// connectionRelationIdentifier returns an identification for the relation this connection may contribute to
func createRelationIdentifier(localEndpoint, remoteEndpoint *endpointID, direction network.ConnectionDirection) string {

	// For directional relations, connections with the same source ip are grouped (port is ignored)
	// For non-directed relations ports are ignored on both sides
	switch direction {
	case network.INCOMING:
		return fmt.Sprintf("in:%s:%s", endpointKey(localEndpoint), endpointKeyNoPort(remoteEndpoint))
	case network.OUTGOING:
		return fmt.Sprintf("out:%s:%s", endpointKeyNoPort(localEndpoint), endpointKey(remoteEndpoint))
	default:
		return fmt.Sprintf("none:%s:%s", endpointKeyNoPort(localEndpoint), endpointKeyNoPort(remoteEndpoint))
	}
}

// makeEndpointID returns a endpointID if the ip is valid and the hostname as the scope for local ips
func makeEndpointID(cfg *config.AgentConfig, netNs uint32, addr util.Address, isV6 bool, port uint16) *endpointID {
	return &endpointID{
		Scope: makeAddressScope(cfg, netNs, addr),
		Endpoint: &endpoint{
			ip: &ip{
				Address: addr.String(),
				IsIPv6:  isV6,
			},
			Port: port,
		},
	}
}

// Represents the scope part of connection identity. The connection scope
// determines its locality (e.g. the scope in which a network address resides)
type scope struct {
	ClusterName      string
	HostName         string
	NetworkNamespace string
}

func (ns scope) toString() string {
	var fragments []string
	if ns.ClusterName != "" {
		fragments = append(fragments, ns.ClusterName)
	}
	if ns.HostName != "" {
		fragments = append(fragments, ns.HostName)
	}
	if ns.NetworkNamespace != "" {
		fragments = append(fragments, ns.NetworkNamespace)
	}
	return strings.Join(fragments, ":")
}

// makeAddressScope Creates a scope in which a network address exists. Networking is always decentralized and local,
// hence we need to add the scope context to make it globally unique. The primary information used for this is the address
// range (loopback/provate/public) aswell as contextual information that was retrieved or configured (cluster/hostname).
func makeAddressScope(cfg *config.AgentConfig, netNs uint32, addr util.Address) string {
	// check if we're running in kubernetes, prepend the scope with the kubernetes / openshift cluster name
	var ns = scope{"", "", ""}

	if addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		// Loopback address, qualify with cluster, host, netns.
		ns.ClusterName = cfg.ClusterName
		ns.HostName = cfg.HostName
		if netNs != 0 {
			ns.NetworkNamespace = strconv.FormatUint(uint64(netNs), 10)
		}
	} else if addr.IsPrivate() {
		// Private address is scoped with the 'private network', which currently can only be the cluster name
		ns.ClusterName = cfg.ClusterName
	} // Otherwise the address is public, no scoping needed.

	return ns.toString()
}

func formatFamily(f network.ConnectionFamily) model.ConnectionFamily {
	switch f {
	case network.AFINET:
		return model.ConnectionFamily_v4
	case network.AFINET6:
		return model.ConnectionFamily_v6
	default:
		return -1
	}
}

func formatType(f network.ConnectionType) model.ConnectionType {
	switch f {
	case network.TCP:
		return model.ConnectionType_tcp
	case network.UDP:
		return model.ConnectionType_udp
	default:
		return -1
	}
}

func calculateDirection(d network.ConnectionDirection) model.ConnectionDirection {
	switch d {
	case network.OUTGOING:
		return model.ConnectionDirection_outgoing
	case network.INCOMING:
		return model.ConnectionDirection_incoming
	default:
		return model.ConnectionDirection_none
	}
}

// retryTracerInit tries to create a network tracer with a given retry duration and retry amount
func retryTracerInit(retryDuration time.Duration, retryAmount int, config *tracerConfig.Config,
	makeTracer func(*tracerConfig.Config, telemetry.Component) (*tracer.Tracer, error)) (*tracer.Tracer, error) {

	retryTicker := time.NewTicker(retryDuration)
	retriesLeft := retryAmount

	var t *tracer.Tracer
	var err error

retry:
	for {
		select {
		case <-retryTicker.C:
			t, err = makeTracer(config, telemetryimpl.GetCompatComponent())
			if err == nil {
				break retry
			}
			retriesLeft = retriesLeft - 1
			if retriesLeft == 0 {
				log.Errorf("failed to create network tracer: %s. No retries left.", err)
				break retry
			}

			log.Warnf("failed to create network tracer: %s. Retrying...", err)
		}
	}

	return t, err
}
