package checks

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/network"
	tracerConfig "github.com/DataDog/datadog-agent/pkg/network/config"
	tracer "github.com/DataDog/datadog-agent/pkg/network/tracer"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/StackVista/stackstate-process-agent/model"

	log "github.com/cihub/seelog"
	"net"
	"strconv"
	"strings"
	"time"
)

type ip struct {
	Address string
	IsIPv6  bool
}

type endpoint struct {
	ip   *ip
	Port uint16
}

type endpointID struct {
	Namespace string
	Endpoint  *endpoint
}

// endpointKey returns a endpointID as namespace:endpoint-ip-address:endpoint-port
func endpointKey(e *endpointID) string {
	var values []string
	values = append(values, e.Namespace)

	if e.Endpoint != nil && e.Endpoint.ip != nil {
		values = append(values, e.Endpoint.ip.Address)
	}

	if e.Endpoint != nil {
		values = append(values, strconv.Itoa(int(e.Endpoint.Port)))
	}

	return strings.Join(values, ":")
}

// endpointKeyNoPort returns a endpointID as scope:namespace:endpoint-ip-address
func endpointKeyNoPort(e *endpointID) string {
	var values []string
	values = append(values, e.Namespace)

	if e.Endpoint != nil && e.Endpoint.ip != nil {
		values = append(values, e.Endpoint.ip.Address)
	}

	return strings.Join(values, ":")
}

// CreateNetworkRelationIdentifier returns an identification for the relation this connection may contribute to
func CreateNetworkRelationIdentifier(namespace string, conn network.ConnectionStats) (string, error) {
	isV6 := conn.Family == network.AFINET6
	localEndpoint, err := makeEndpointID(namespace, conn.Source, isV6, conn.SPort)
	if err != nil {
		return "", err
	}
	remoteEndpoint, err := makeEndpointID(namespace, conn.Dest, isV6, conn.DPort)
	if err != nil {
		return "", err
	}
	return createRelationIdentifier(localEndpoint, remoteEndpoint, conn.Direction), nil
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
func makeEndpointID(namespace string, addr util.Address, isV6 bool, port uint16) (*endpointID, error) {
	endpoint := &endpointID{
		Namespace: namespace,
		Endpoint: &endpoint{
			ip: &ip{
				Address: addr.String(),
				IsIPv6:  isV6,
			},
			Port: port,
		},
	}

	return endpoint, nil
}

// Represents the namespace part of connection identity. The connection namespace
// determines its locality (e.g. the scope in which the network resides)
type namespace struct {
	ClusterName      string
	HostName         string
	NetworkNamespace string
}

func (ns namespace) toString() string {
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

func makeNamespace(clusterName string, hostname string, connection network.ConnectionStats) namespace {
	// check if we're running in kubernetes, prepend the namespace with the kubernetes / openshift cluster name
	var ns = namespace{"", "", ""}
	if clusterName != "" {
		ns.ClusterName = clusterName
	}

	if connection.Source.IsLoopback() && connection.Dest.IsLoopback() {
		// For sure this is scoped to the host
		ns.HostName = hostname
		// Maybe even to a namespace on the host in case of k8s/docker containers
		if connection.NetNS != 0 {
			ns.NetworkNamespace = strconv.Itoa(int(connection.NetNS))
		}
	}

	return ns
}

func formatNamespace(clusterName string, hostname string, connection network.ConnectionStats) string {
	return makeNamespace(clusterName, hostname, connection).toString()
}

func isLoopback(ip string) bool {
	ipAddress := net.ParseIP(ip)
	if ipAddress == nil {
		return false
	}
	return ipAddress.IsLoopback()
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
	makeTracer func(*tracerConfig.Config) (*tracer.Tracer, error)) (*tracer.Tracer, error) {

	retryTicker := time.NewTicker(retryDuration)
	retriesLeft := retryAmount

	var t *tracer.Tracer
	var err error

retry:
	for {
		select {
		case <-retryTicker.C:
			t, err = makeTracer(config)
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
