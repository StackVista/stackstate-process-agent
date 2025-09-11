package checks

import (
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/pkg/kube"
	"github.com/StackVista/stackstate-process-agent/pkg/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func sortOTELMetricsByName(metrics []metricdata.Metrics) {
	slices.SortFunc(metrics, func(a, b metricdata.Metrics) int {
		return strings.Compare(a.Name, b.Name)
	})
}

func assertInt64Metric(t *testing.T, m metricdata.Metrics, expectedName string, expectedDatapoint metricdata.DataPoint[int64]) {
	require.Equal(t, expectedName, m.Name)
	require.IsType(t, metricdata.Sum[int64]{}, m.Data)

	data := m.Data.(metricdata.Sum[int64])
	require.Len(t, data.DataPoints, 1)
	dp := data.DataPoints[0]
	require.Equal(t, expectedDatapoint.Value, dp.Value)
	require.Equal(t, expectedDatapoint.Attributes, dp.Attributes)
}

func updateConnStatsDuration(conn network.ConnectionStats, duration time.Duration) network.ConnectionStats {
	conn.Duration = duration
	return conn
}

func updateRemoteIP(conn network.ConnectionStats, ip util.Address) network.ConnectionStats {
	conn.Dest = ip
	return conn
}

func updateLocalIP(conn network.ConnectionStats, ip util.Address) network.ConnectionStats {
	conn.Source = ip
	return conn
}

func TestPodCorrelation(t *testing.T) {
	var (
		rm metricdata.ResourceMetrics

		postgresClientIP            = util.AddressFromString("10.244.0.2")
		postgresClientPodName       = "postgres-client"
		postgresClientLabels        = map[string]string{"app": "client"}
		postgresServerIP            = util.AddressFromString("10.244.0.3")
		postgresServerPodName       = "postgres-server"
		postgresServerLabels        = map[string]string{"app": "server"}
		postgresServerPort          = uint16(5432)
		postgresClientPort          = uint16(12345)
		postgresNamespace           = "default"
		postgresServerNs            = uint32(4026534025)
		postgresClientNs            = uint32(4026534026)
		postgresClientReceivedBytes = int64(111)
		postgresClientSentBytes     = int64(222)

		// pod in hostNetwork will have this IP
		hostIP              = util.AddressFromString("192.168.1.7")
		localhostIP         = util.AddressFromString("127.0.0.1")
		randomLocalHostPort = uint16(46734)
	)

	defaultPostgresOutgoingConnection := network.ConnectionStats{
		ConnectionTuple: network.ConnectionTuple{
			Type:      network.TCP,
			Direction: network.OUTGOING,
			Source:    postgresClientIP,
			SPort:     postgresClientPort,
			Dest:      postgresServerIP,
			DPort:     postgresServerPort,
			NetNS:     postgresClientNs,
		},
		Duration: 10 * time.Second,
		Last: network.StatCounters{
			RecvBytes: uint64(postgresClientReceivedBytes),
			SentBytes: uint64(postgresClientSentBytes),
		},
	}

	defaultPostgresIncomingConnection := network.ConnectionStats{
		ConnectionTuple: network.ConnectionTuple{
			Type:      network.TCP,
			Direction: network.INCOMING,
			// Incoming connection so fields are inverted
			Source: postgresServerIP,
			SPort:  postgresServerPort,
			Dest:   postgresClientIP,
			DPort:  postgresClientPort,
			NetNS:  postgresServerNs,
		},
		Duration: 10 * time.Second,
		Last: network.StatCounters{
			RecvBytes: uint64(postgresClientSentBytes),
			SentBytes: uint64(postgresClientReceivedBytes),
		},
	}

	postgresClientPodInfo := kube.PodInfo{
		Namespace:         postgresNamespace,
		Name:              postgresClientPodName,
		Labels:            postgresClientLabels,
		CreationTimestamp: 40,
		DeletionTimestamp: 0,
	}

	postgresServerPodInfo := kube.PodInfo{
		Namespace:         postgresNamespace,
		Name:              postgresServerPodName,
		Labels:            postgresServerLabels,
		CreationTimestamp: 41,
		DeletionTimestamp: 0,
	}

	tests := []struct {
		name                     string
		exportProtocolMetrics    bool
		exportPartialCorrelation bool
		testBody                 func(t *testing.T, pi *podCorrelationInfo)
	}{
		{
			name:                     "simple pod outgoing connection",
			exportProtocolMetrics:    false,
			exportPartialCorrelation: false,
			testBody: func(t *testing.T, pi *podCorrelationInfo) {
				conn := defaultPostgresOutgoingConnection
				pi.processConnections([]network.ConnectionStats{conn}, nil)

				// Read metrics: TODO!: this seems duplicated
				require.NoError(t, pi.metrics.Reader.Collect(t.Context(), &rm))
				require.Len(t, rm.ScopeMetrics, 1)
				require.Len(t, rm.ScopeMetrics[0].Metrics, 2)
				metrics := rm.ScopeMetrics[0].Metrics
				sortOTELMetricsByName(metrics)

				attrs := pi.getMetricAttributes(&conn, &postgresClientPodInfo, &postgresServerPodInfo)
				assertInt64Metric(t, metrics[0], telemetry.ReceivedMetricName, metricdata.DataPoint[int64]{
					Value:      postgresClientReceivedBytes,
					Attributes: attribute.NewSet(attrs...),
				})
				assertInt64Metric(t, metrics[1], telemetry.SentMetricName, metricdata.DataPoint[int64]{
					Value:      postgresClientSentBytes,
					Attributes: attribute.NewSet(attrs...),
				})
			},
		},
		{
			name:                     "simple pod incoming connection",
			exportProtocolMetrics:    false,
			exportPartialCorrelation: false,
			testBody: func(t *testing.T, pi *podCorrelationInfo) {
				conn := defaultPostgresIncomingConnection
				pi.processConnections([]network.ConnectionStats{conn}, nil)

				// Read metrics
				require.NoError(t, pi.metrics.Reader.Collect(t.Context(), &rm))
				require.Len(t, rm.ScopeMetrics, 1)
				require.Len(t, rm.ScopeMetrics[0].Metrics, 2)
				metrics := rm.ScopeMetrics[0].Metrics
				sortOTELMetricsByName(metrics)

				attrs := pi.getMetricAttributes(&conn, &postgresServerPodInfo, &postgresClientPodInfo)
				assertInt64Metric(t, metrics[0], telemetry.ReceivedMetricName, metricdata.DataPoint[int64]{
					Value:      postgresClientSentBytes,
					Attributes: attribute.NewSet(attrs...),
				})
				assertInt64Metric(t, metrics[1], telemetry.SentMetricName, metricdata.DataPoint[int64]{
					Value:      postgresClientReceivedBytes,
					Attributes: attribute.NewSet(attrs...),
				})
			},
		},
		{
			name:                     "process stored connection",
			exportProtocolMetrics:    false,
			exportPartialCorrelation: false,
			testBody: func(t *testing.T, pi *podCorrelationInfo) {
				// this connection will be store 89 + boot_time(30) = 119 > now(120) - maxlatency(5)
				pi.processConnections([]network.ConnectionStats{updateConnStatsDuration(defaultPostgresIncomingConnection, 89*time.Second)}, nil)

				// The connection was too young and stored.
				require.NoError(t, pi.metrics.Reader.Collect(t.Context(), &rm))
				require.Len(t, rm.ScopeMetrics, 0)
				require.Len(t, pi.storedConnections, 1)

				// if we call it again we process the stored connection
				pi.processConnections([]network.ConnectionStats{}, nil)
				require.NoError(t, pi.metrics.Reader.Collect(t.Context(), &rm))
				require.Len(t, rm.ScopeMetrics, 1)
				require.Len(t, rm.ScopeMetrics[0].Metrics, 2)
				require.Len(t, pi.storedConnections, 0)
			},
		},
		{
			name:                     "invalid pod incoming connection",
			exportProtocolMetrics:    false,
			exportPartialCorrelation: false, // nothing would change if we enable partial correlation
			testBody: func(t *testing.T, pi *podCorrelationInfo) {
				// before: postgres-client -> postgres-server
				// after: hostIP -> hostIP
				pi.processConnections([]network.ConnectionStats{updateLocalIP(updateRemoteIP(defaultPostgresIncomingConnection, hostIP), hostIP)}, nil)

				// no metrics to be exported
				require.NoError(t, pi.metrics.Reader.Collect(t.Context(), &rm))
				require.Len(t, rm.ScopeMetrics, 0)
				require.Len(t, pi.storedConnections, 0)
			},
		},
		{
			name:                     "partial correlation disabled",
			exportProtocolMetrics:    false,
			exportPartialCorrelation: false,
			testBody: func(t *testing.T, pi *podCorrelationInfo) {
				// since we have an incoming connection to update the postgres client we need to override the remote IP
				// before: postgres-client -> postgres-server
				// after: hostIP -> postgres-server
				pi.processConnections([]network.ConnectionStats{updateRemoteIP(defaultPostgresIncomingConnection, hostIP)}, nil)
				// we don't enable partialCorrelation and so we don't expect any metrics to be exported
				require.NoError(t, pi.metrics.Reader.Collect(t.Context(), &rm))
				require.Len(t, rm.ScopeMetrics, 0)
				require.Len(t, pi.storedConnections, 0)
			},
		},
		{
			name:                     "partial correlation enabled incoming missing remote",
			exportProtocolMetrics:    false,
			exportPartialCorrelation: true,
			testBody: func(t *testing.T, pi *podCorrelationInfo) {
				// before: postgres-client -> postgres-server
				// after: hostIP -> postgres-server
				conn := updateRemoteIP(defaultPostgresIncomingConnection, hostIP)
				pi.processConnections([]network.ConnectionStats{conn}, nil)
				require.NoError(t, pi.metrics.Reader.Collect(t.Context(), &rm))
				require.Len(t, rm.ScopeMetrics, 1)
				require.Len(t, rm.ScopeMetrics[0].Metrics, 2)
				metrics := rm.ScopeMetrics[0].Metrics
				sortOTELMetricsByName(metrics)

				attrs := pi.getMetricAttributes(&conn, &postgresServerPodInfo, nil)
				assertInt64Metric(t, metrics[0], telemetry.ReceivedMetricName, metricdata.DataPoint[int64]{
					// The connection is incoming so they recv/sent are inverted.
					Value:      222,
					Attributes: attribute.NewSet(attrs...),
				})
				assertInt64Metric(t, metrics[1], telemetry.SentMetricName, metricdata.DataPoint[int64]{
					Value:      111,
					Attributes: attribute.NewSet(attrs...),
				})
			},
		},
		{
			name:                     "partial correlation enabled incoming missing local",
			exportProtocolMetrics:    false,
			exportPartialCorrelation: true,
			testBody: func(t *testing.T, pi *podCorrelationInfo) {
				// before: postgres-client -> postgres-server
				// after: postgres-client -> hostIP
				conn := updateLocalIP(defaultPostgresIncomingConnection, hostIP)
				// this is now an incoming connection on the host network so we should also change the netns to 0.
				// since the connection is in the root netns we will filter it out
				conn.NetNS = 0
				pi.processConnections([]network.ConnectionStats{conn}, nil)
				require.NoError(t, pi.metrics.Reader.Collect(t.Context(), &rm))
				require.Len(t, rm.ScopeMetrics, 0)
				require.Len(t, pi.storedConnections, 0)
			},
		},
		{
			name:                     "localhost outgoing",
			exportProtocolMetrics:    false,
			exportPartialCorrelation: true,
			testBody: func(t *testing.T, pi *podCorrelationInfo) {
				// this is an outgoing connection inside the pod (localhost -> localhost)
				conn := network.ConnectionStats{
					ConnectionTuple: network.ConnectionTuple{
						Type:      network.TCP,
						Direction: network.OUTGOING,
						// Outgoing connection so fields are not inverted
						Source: localhostIP,
						SPort:  randomLocalHostPort,
						Dest:   localhostIP,
						DPort:  randomLocalHostPort,
						// we suppose this is in the server pod netns
						NetNS: postgresServerNs,
					},
					Duration: 10 * time.Second,
				}
				pi.processConnections([]network.ConnectionStats{conn}, nil)
				require.NoError(t, pi.metrics.Reader.Collect(t.Context(), &rm))
				require.Len(t, rm.ScopeMetrics, 0)
				require.Len(t, pi.storedConnections, 0)
			},
		},
		{
			name:                     "localhost incoming",
			exportProtocolMetrics:    false,
			exportPartialCorrelation: true,
			testBody: func(t *testing.T, pi *podCorrelationInfo) {
				// this is an incoming connection inside the pod (localhost -> localhost)
				conn := network.ConnectionStats{
					ConnectionTuple: network.ConnectionTuple{
						Type:      network.TCP,
						Direction: network.INCOMING,
						Source:    localhostIP,
						SPort:     randomLocalHostPort,
						Dest:      localhostIP,
						DPort:     randomLocalHostPort,
						// we suppose this is in the server pod netns
						NetNS: postgresServerNs,
					},
					Duration: 10 * time.Second,
				}
				pi.processConnections([]network.ConnectionStats{conn}, nil)
				require.NoError(t, pi.metrics.Reader.Collect(t.Context(), &rm))
				require.Len(t, rm.ScopeMetrics, 0)
				require.Len(t, pi.storedConnections, 0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			///////////////////////////
			// Create a mock observer with an initial state.
			///////////////////////////
			reg := prometheus.NewRegistry()
			obs, err := kube.NewObserver(reg,
				kube.WithBootTime(time.Unix(30, 0)),
				kube.WithNowFunc(func() time.Time { return time.Unix(120, 0) }),
				kube.WithMaxControlPlaneLatency(5*time.Second),
				kube.WithLastControlPlaneLatency(1*time.Second),
				kube.WithPodsByIP(map[util.Address][]*kube.PodInfo{
					postgresClientIP: {&postgresClientPodInfo},
					postgresServerIP: {&postgresServerPodInfo},
				}))
			require.NoError(t, err)

			///////////////////////////
			// Create a pod correlation info struct with a manual exporter
			///////////////////////////
			pi, err := newPodCorrelationInfo(
				&config.PodCorrelationConfig{
					Enabled:            true,
					ProtocolMetrics:    tt.exportProtocolMetrics,
					PartialCorrelation: tt.exportPartialCorrelation,
					Exporter: config.ExporterConfig{
						Type: config.ExporterTypeManual,
					},
					AttributesKeys:   AllAttributeKeys,
					ObserverLogLevel: "debug",
				})
			require.NoError(t, err)
			// Overwrite the observer in the pod correlation struct
			pi.observer = obs

			///////////////////////////
			// Run test body
			///////////////////////////
			tt.testBody(t, pi)
		})
	}
}

// this test is used to understand the behavior of the sketch ForEach function
func TestSketchForEach(t *testing.T) {
	sketch := emptySketch()
	sketch.Add(1)
	sketch.Add(1)
	sketch.Add(2)
	sketch.Add(2)
	sketch.Add(3)
	sketch.Add(1)

	seen := make(map[int64]int64)
	sketch.ForEach(func(value, count float64) (stop bool) {
		seen[int64(math.Round(value))] += int64(count)
		// False because we want to iterate on all samples.
		return false
	})
	require.Equal(t, map[int64]int64{
		1: 3,
		2: 2,
		3: 1,
	}, seen)
}

func TestGetMetricAttributes(t *testing.T) {
	clientIP := util.AddressFromString("10.0.0.10")
	serverIP := util.AddressFromString("10.0.0.20")
	clientPort := uint16(12345)
	serverPort := uint16(5432)

	// Keys are already in OTEL in the podInfo struct
	label1Key := "app.kubernetes.io.instance"
	label1ValueClient := "client"
	label1ValueServer := "server"
	label2Key := "pod.template.hash"
	label2ValueClient := "hash1"
	label2ValueServer := "hash2"
	remoteLabel1OTELKey := fmt.Sprintf("%s.%s", RemoteLabelsKey, label1Key)
	remoteLabel2OTELKey := fmt.Sprintf("%s.%s", RemoteLabelsKey, label2Key)
	localLabel1OTELKey := fmt.Sprintf("%s.%s", LocalLabelsKey, label1Key)
	localLabel2OTELKey := fmt.Sprintf("%s.%s", LocalLabelsKey, label2Key)

	clientPod := &kube.PodInfo{
		Namespace: "default-client",
		Name:      "client-pod",
		Labels:    map[string]string{label1Key: label1ValueClient, label2Key: label2ValueClient},
	}
	serverPod := &kube.PodInfo{
		Namespace: "default-server",
		Name:      "server-pod",
		Labels:    map[string]string{label1Key: label1ValueServer, label2Key: label2ValueServer},
	}

	outgoing := network.ConnectionStats{
		ConnectionTuple: network.ConnectionTuple{
			Source:    clientIP,
			SPort:     clientPort,
			Dest:      serverIP,
			DPort:     serverPort,
			Direction: network.OUTGOING,
		},
	}

	allAttributes := []attribute.KeyValue{
		attribute.String(LocalIPKey, clientIP.String()),
		attribute.String(LocalPortKey, fmt.Sprintf("%d", clientPort)),
		attribute.String(LocalPodNameKey, clientPod.Name),
		attribute.String(LocalNSKey, clientPod.Namespace),
		attribute.String(localLabel1OTELKey, label1ValueClient),
		attribute.String(localLabel2OTELKey, label2ValueClient),

		attribute.String(RemoteIPKey, serverIP.String()),
		attribute.String(RemotePortKey, fmt.Sprintf("%d", serverPort)),
		attribute.String(RemotePodNameKey, serverPod.Name),
		attribute.String(RemoteNSKey, serverPod.Namespace),
		attribute.String(remoteLabel1OTELKey, label1ValueServer),
		attribute.String(remoteLabel2OTELKey, label2ValueServer),

		attribute.String(DirectionKey, connectionDirectionToString(outgoing.Direction)),
	}

	clientAttr := []attribute.KeyValue{
		attribute.String(LocalIPKey, clientIP.String()),
		attribute.String(LocalPortKey, fmt.Sprintf("%d", clientPort)),
		attribute.String(LocalPodNameKey, clientPod.Name),
		attribute.String(LocalNSKey, clientPod.Namespace),
		attribute.String(localLabel1OTELKey, label1ValueClient),
		attribute.String(localLabel2OTELKey, label2ValueClient),

		attribute.String(RemoteIPKey, serverIP.String()),
		attribute.String(RemotePortKey, fmt.Sprintf("%d", serverPort)),

		attribute.String(DirectionKey, connectionDirectionToString(outgoing.Direction)),
	}
	serverAttr := []attribute.KeyValue{
		attribute.String(LocalIPKey, clientIP.String()),
		attribute.String(LocalPortKey, fmt.Sprintf("%d", clientPort)),

		attribute.String(RemoteIPKey, serverIP.String()),
		attribute.String(RemotePortKey, fmt.Sprintf("%d", serverPort)),
		attribute.String(RemotePodNameKey, serverPod.Name),
		attribute.String(RemoteNSKey, serverPod.Namespace),
		attribute.String(remoteLabel1OTELKey, label1ValueServer),
		attribute.String(remoteLabel2OTELKey, label2ValueServer),

		attribute.String(DirectionKey, connectionDirectionToString(outgoing.Direction)),
	}

	tests := []struct {
		name                   string
		conn                   network.ConnectionStats
		want                   []attribute.KeyValue
		localPod               *kube.PodInfo
		remotePod              *kube.PodInfo
		requiredAttributesKeys []string
	}{
		{
			name:                   "outgoing_both_pods",
			conn:                   outgoing,
			localPod:               clientPod,
			remotePod:              serverPod,
			requiredAttributesKeys: AllAttributeKeys,
			want:                   allAttributes,
		},
		{
			name:                   "outgoing_both_pods_limited_required_attrs",
			conn:                   outgoing,
			localPod:               clientPod,
			remotePod:              serverPod,
			requiredAttributesKeys: DefaultAttributeKeys,
			want: []attribute.KeyValue{
				attribute.String(LocalPodNameKey, clientPod.Name),
				attribute.String(LocalNSKey, clientPod.Namespace),
				attribute.String(localLabel1OTELKey, label1ValueClient),
				attribute.String(localLabel2OTELKey, label2ValueClient),
				attribute.String(RemotePodNameKey, serverPod.Name),
				attribute.String(RemoteNSKey, serverPod.Namespace),
				attribute.String(DirectionKey, connectionDirectionToString(outgoing.Direction)),
			},
		},
		{
			name:                   "outgoing_missing_dst_pod_only_client_attrs",
			conn:                   outgoing,
			localPod:               clientPod,
			remotePod:              nil,
			requiredAttributesKeys: AllAttributeKeys,
			want:                   clientAttr,
		},
		{
			name:                   "outgoing_missing_src_pod_only_server_attrs",
			conn:                   outgoing,
			localPod:               nil,
			remotePod:              serverPod,
			requiredAttributesKeys: AllAttributeKeys,
			want:                   serverAttr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pi, err := newPodCorrelationInfo(
				&config.PodCorrelationConfig{
					Exporter: config.ExporterConfig{
						Type: config.ExporterTypeDisabled,
					},
					AttributesKeys: tt.requiredAttributesKeys,
				},
			)
			require.NoError(t, err)

			got := pi.getMetricAttributes(&tt.conn, tt.localPod, tt.remotePod)
			require.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestAttributesKeysLen(t *testing.T) {
	require.Equal(t, numAttributeKeys, len(AllAttributeKeys), "Please update the AllAttributeKeys variable in net_pod_correlation.go if you added a new attribute key")
}

func TestValidateAttributeKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "valid_set",
			input:    AllAttributeKeys,
			expected: AllAttributeKeys,
		},
		{
			name:     "invalid_key",
			input:    []string{LocalIPKey, "invalid.key"},
			expected: nil,
		},
		{
			name:     "empty_set",
			input:    []string{},
			expected: DefaultAttributeKeys,
		},
		{
			name:     "duplicate_keys",
			input:    []string{LocalIPKey, LocalIPKey, RemoteIPKey},
			expected: []string{LocalIPKey, RemoteIPKey},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateAttributeKeys(tt.input)

			if tt.expected == nil {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.ElementsMatch(t, tt.expected, got)

		})
	}

}
