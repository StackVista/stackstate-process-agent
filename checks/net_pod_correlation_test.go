//go:build test

package checks

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
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

func updateDstIP(conn network.ConnectionStats, ip util.Address) network.ConnectionStats {
	conn.Dest = ip
	return conn
}

func updateSrcIP(conn network.ConnectionStats, ip util.Address) network.ConnectionStats {
	conn.Source = ip
	return conn
}

// Example of ScopeMetrics
// 	"ScopeMetrics": [
//     {
//         "Scope": {
//             "Name": "network",
//             "Version": "",
//             "SchemaURL": "",
//             "Attributes": null
//         },
//         "Metrics": [
//             {
//                 "Name": "agent.network.sent",
//                 "Description": "Total number of bytes sent",
//                 "Unit": "By",
//                 "Data": {
//                     "DataPoints": [
//                         {
//                             "Attributes": [
//                                 {
//                                     "Key": "dst.ip",
//                                     "Value": {
//                                         "Type": "STRING",
//                                         "Value": "10.42.0.10"
//                                     }
//                                 },
//                                 {
//                                     "Key": "dst.labels",
//                                     "Value": {
//                                         "Type": "STRING",
//                                         "Value": "[app=postgres-server pod-template-hash=5bc9fb79b]"
//                                     }
//                                 },
//                                 {
//                                     "Key": "dst.namespace",
//                                     "Value": {
//                                         "Type": "STRING",
//                                         "Value": "default"
//                                     }
//                                 },
//                                 {
//                                     "Key": "dst.pod",
//                                     "Value": {
//                                         "Type": "STRING",
//                                         "Value": "postgres-server-5bc9fb79b-src29"
//                                     }
//                                 },
//                                 {
//                                     "Key": "dst.port",
//                                     "Value": {
//                                         "Type": "STRING",
//                                         "Value": "54964"
//                                     }
//                                 },
//                                 {
//                                     "Key": "netns",
//                                     "Value": {
//                                         "Type": "STRING",
//                                         "Value": "4026534025"
//                                     }
//                                 },
//                                 {
//                                     "Key": "src.ip",
//                                     "Value": {
//                                         "Type": "STRING",
//                                         "Value": "10.42.0.9"
//                                     }
//                                 },
//                                 {
//                                     "Key": "src.labels",
//                                     "Value": {
//                                         "Type": "STRING",
//                                         "Value": "[app=postgres-client pod-template-hash=796f8c67c7]"
//                                     }
//                                 },
//                                 {
//                                     "Key": "src.namespace",
//                                     "Value": {
//                                         "Type": "STRING",
//                                         "Value": "default"
//                                     }
//                                 },
//                                 {
//                                     "Key": "src.pod",
//                                     "Value": {
//                                         "Type": "STRING",
//                                         "Value": "postgres-client-796f8c67c7-pv8gt"
//                                     }
//                                 }
//                             ],
//                             "StartTime": "2025-08-20T10:44:36.452144221+02:00",
//                             "Time": "2025-08-20T10:53:51.452332986+02:00",
//                             "Value": 13500
//                         }
//                     ],
//                     "Temporality": "CumulativeTemporality",
//                     "IsMonotonic": true
//                 }
//             }
//         ]
//     }
// ]

func TestPodCorrelation(t *testing.T) {
	var (
		rm metricdata.ResourceMetrics

		postgresClientIP      = util.AddressFromString("10.244.0.2")
		postgresClientPodName = "postgres-client"
		postgresClientLabels  = "app=client"
		postgresServerIP      = util.AddressFromString("10.244.0.3")
		postgresServerPodName = "postgres-server"
		postgresServerLabels  = "app=server"
		postgresServerPort    = uint16(5432)
		postgresNamespace     = "default"
		postgresServerNs      = uint32(4026534025)

		// pod in hostNetwork will have this IP
		hostIP = util.AddressFromString("192.168.1.7")
		hostNs = uint32(1)
	)

	defaultPostgresIncomingConnection := network.ConnectionStats{
		ConnectionTuple: network.ConnectionTuple{
			Type:      network.TCP,
			Direction: network.INCOMING,
			// Incoming connection so fields are inverted
			Source: postgresServerIP,
			SPort:  postgresServerPort,
			Dest:   postgresClientIP,
			NetNS:  postgresServerNs,
		},
		Duration: 10 * time.Second,
		Last: network.StatCounters{
			RecvBytes: 111,
			SentBytes: 222,
		},
	}

	tests := []struct {
		name                     string
		conn                     []network.ConnectionStats
		protoMetrics             map[connKey][]*model.ConnectionMetric
		exportProtocolMetrics    bool
		exportPartialCorrelation bool
		testBody                 func(t *testing.T, pi *podCorrelationInfo, conns []network.ConnectionStats, protoMetrics map[connKey][]*model.ConnectionMetric)
	}{
		{
			name: "simple pod incoming connection",
			conn: []network.ConnectionStats{
				defaultPostgresIncomingConnection,
			},
			exportProtocolMetrics:    false,
			exportPartialCorrelation: false,
			testBody: func(t *testing.T, pi *podCorrelationInfo, conns []network.ConnectionStats, protoMetrics map[connKey][]*model.ConnectionMetric) {
				pi.processConnections(conns, protoMetrics)

				// Read metrics
				require.NoError(t, pi.metrics.Reader.Collect(context.Background(), &rm))
				require.Len(t, rm.ScopeMetrics, 1)
				require.Len(t, rm.ScopeMetrics[0].Metrics, 2)
				metrics := rm.ScopeMetrics[0].Metrics
				sortOTELMetricsByName(metrics)

				attributeSet := attribute.NewSet(
					attribute.String(SrcIPKey, postgresClientIP.String()),
					attribute.String(SrcPodKey, postgresClientPodName),
					attribute.String(SrcNSKey, postgresNamespace),
					attribute.String(SrcLabelsKey, postgresClientLabels),

					attribute.String(DstIPKey, postgresServerIP.String()),
					attribute.String(DstPodKey, postgresServerPodName),
					attribute.String(DstNSKey, postgresNamespace),
					attribute.String(DstLabelsKey, postgresServerLabels),
					attribute.String(DstPortKey, fmt.Sprintf("%d", postgresServerPort)),
				)
				assertInt64Metric(t, metrics[0], telemetry.ReceivedMetricName, metricdata.DataPoint[int64]{
					// The connection is incoming so they recv/sent are inverted.
					Value:      222,
					Attributes: attributeSet,
				})
				assertInt64Metric(t, metrics[1], telemetry.SentMetricName, metricdata.DataPoint[int64]{
					Value:      111,
					Attributes: attributeSet,
				})
			},
		},
		{
			name: "process stored connection",
			conn: []network.ConnectionStats{
				// this connection will be store 89 + boot_time(30) = 119 > now(120) - maxlatency(5)
				updateConnStatsDuration(defaultPostgresIncomingConnection, 89*time.Second),
			},
			exportProtocolMetrics:    false,
			exportPartialCorrelation: false,
			testBody: func(t *testing.T, pi *podCorrelationInfo, conns []network.ConnectionStats, protoMetrics map[connKey][]*model.ConnectionMetric) {
				pi.processConnections(conns, protoMetrics)
				// The connection was too young and stored.
				require.NoError(t, pi.metrics.Reader.Collect(context.Background(), &rm))
				require.Len(t, rm.ScopeMetrics, 0)
				require.Len(t, pi.storedConnections, 1)

				// if we call it again we process the stored connection
				pi.processConnections([]network.ConnectionStats{}, protoMetrics)
				require.NoError(t, pi.metrics.Reader.Collect(context.Background(), &rm))
				require.Len(t, rm.ScopeMetrics, 1)
				require.Len(t, rm.ScopeMetrics[0].Metrics, 2)
				require.Len(t, pi.storedConnections, 0)
			},
		},
		{
			name: "invalid pod incoming connection",
			conn: []network.ConnectionStats{
				// before: postgres-client -> postgres-server
				// after: hostIP -> hostIP
				updateSrcIP(updateDstIP(defaultPostgresIncomingConnection, hostIP), hostIP),
			},
			exportProtocolMetrics:    false,
			exportPartialCorrelation: false, // nothing would change if we enable partial correlation
			testBody: func(t *testing.T, pi *podCorrelationInfo, conns []network.ConnectionStats, protoMetrics map[connKey][]*model.ConnectionMetric) {
				pi.processConnections(conns, protoMetrics)
				// no metrics to be exported
				require.NoError(t, pi.metrics.Reader.Collect(context.Background(), &rm))
				require.Len(t, rm.ScopeMetrics, 0)
				require.Len(t, pi.storedConnections, 0)
			},
		},
		{
			name: "partial correlation disabled",
			conn: []network.ConnectionStats{
				// since we have an incoming connection to update the client we need to override the destination IP
				// before: postgres-client -> postgres-server
				// after: hostIP -> postgres-server
				updateDstIP(defaultPostgresIncomingConnection, hostIP),
			},
			exportProtocolMetrics:    false,
			exportPartialCorrelation: false,
			testBody: func(t *testing.T, pi *podCorrelationInfo, conns []network.ConnectionStats, protoMetrics map[connKey][]*model.ConnectionMetric) {
				pi.processConnections(conns, protoMetrics)
				// we don't enable partialCorrelation and so we don't expect any metrics to be exported
				require.NoError(t, pi.metrics.Reader.Collect(context.Background(), &rm))
				require.Len(t, rm.ScopeMetrics, 0)
				require.Len(t, pi.storedConnections, 0)
			},
		},
		{
			name: "partial correlation enabled missing client",
			conn: []network.ConnectionStats{
				// since we have an incoming connection to update the client we need to override the destination IP
				// before: postgres-client -> postgres-server
				// after: hostIP -> postgres-server
				updateDstIP(defaultPostgresIncomingConnection, hostIP),
			},
			exportProtocolMetrics:    false,
			exportPartialCorrelation: true,
			testBody: func(t *testing.T, pi *podCorrelationInfo, conns []network.ConnectionStats, protoMetrics map[connKey][]*model.ConnectionMetric) {
				pi.processConnections(conns, protoMetrics)
				require.NoError(t, pi.metrics.Reader.Collect(context.Background(), &rm))
				require.Len(t, rm.ScopeMetrics, 1)
				require.Len(t, rm.ScopeMetrics[0].Metrics, 2)
				metrics := rm.ScopeMetrics[0].Metrics
				sortOTELMetricsByName(metrics)

				attributeSet := attribute.NewSet(
					// we miss all the pod attributes on the client
					attribute.String(SrcIPKey, hostIP.String()),
					attribute.String(DstIPKey, postgresServerIP.String()),
					attribute.String(DstPortKey, fmt.Sprintf("%d", postgresServerPort)),

					attribute.String(DstPodKey, postgresServerPodName),
					attribute.String(DstNSKey, postgresNamespace),
					attribute.String(DstLabelsKey, postgresServerLabels),
				)
				assertInt64Metric(t, metrics[0], telemetry.ReceivedMetricName, metricdata.DataPoint[int64]{
					// The connection is incoming so they recv/sent are inverted.
					Value:      222,
					Attributes: attributeSet,
				})
				assertInt64Metric(t, metrics[1], telemetry.SentMetricName, metricdata.DataPoint[int64]{
					Value:      111,
					Attributes: attributeSet,
				})
			},
		},
		{
			name: "partial correlation enabled missing server",
			conn: []network.ConnectionStats{
				// before: postgres-client -> postgres-server
				// after: postgres-client -> hostIP
				updateSrcIP(defaultPostgresIncomingConnection, hostIP),
			},
			exportProtocolMetrics:    false,
			exportPartialCorrelation: true,
			testBody: func(t *testing.T, pi *podCorrelationInfo, conns []network.ConnectionStats, protoMetrics map[connKey][]*model.ConnectionMetric) {
				pi.processConnections(conns, protoMetrics)
				require.NoError(t, pi.metrics.Reader.Collect(context.Background(), &rm))
				require.Len(t, rm.ScopeMetrics, 1)
				require.Len(t, rm.ScopeMetrics[0].Metrics, 2)
				metrics := rm.ScopeMetrics[0].Metrics
				sortOTELMetricsByName(metrics)

				attributeSet := attribute.NewSet(
					// we miss all the pod attributes on the server
					attribute.String(SrcIPKey, postgresClientIP.String()),
					attribute.String(DstIPKey, hostIP.String()),
					attribute.String(DstPortKey, fmt.Sprintf("%d", postgresServerPort)),

					attribute.String(SrcPodKey, postgresClientPodName),
					attribute.String(SrcNSKey, postgresNamespace),
					attribute.String(SrcLabelsKey, postgresClientLabels),
				)
				assertInt64Metric(t, metrics[0], telemetry.ReceivedMetricName, metricdata.DataPoint[int64]{
					// The connection is incoming so they recv/sent are inverted.
					Value:      222,
					Attributes: attributeSet,
				})
				assertInt64Metric(t, metrics[1], telemetry.SentMetricName, metricdata.DataPoint[int64]{
					Value:      111,
					Attributes: attributeSet,
				})
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
					postgresClientIP: {&kube.PodInfo{
						Namespace:         postgresNamespace,
						Name:              postgresClientPodName,
						Labels:            postgresClientLabels,
						CreationTimestamp: 40,
						DeletionTimestamp: 0,
					}},
					postgresServerIP: {&kube.PodInfo{
						Namespace:         postgresNamespace,
						Name:              postgresServerPodName,
						Labels:            postgresServerLabels,
						CreationTimestamp: 41,
						DeletionTimestamp: 0,
					}},
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
				},
				"DEBUG",
				hostNs)
			require.NoError(t, err)
			// Overwrite the observer in the pod correlation struct
			pi.observer = obs

			///////////////////////////
			// Run test body
			///////////////////////////
			tt.testBody(t, pi, tt.conn, tt.protoMetrics)
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
	serverPort := uint16(5432)

	clientPod := &kube.PodInfo{
		Namespace: "default-client",
		Name:      "client-pod",
		Labels:    "app=client",
	}
	serverPod := &kube.PodInfo{
		Namespace: "default-server",
		Name:      "server-pod",
		Labels:    "app=server",
	}

	outgoing := network.ConnectionStats{
		ConnectionTuple: network.ConnectionTuple{
			Source:    clientIP,
			Dest:      serverIP,
			DPort:     serverPort,
			Direction: network.OUTGOING,
		},
	}
	incoming := network.ConnectionStats{
		ConnectionTuple: network.ConnectionTuple{
			Source:    serverIP,
			Dest:      clientIP,
			SPort:     serverPort,
			Direction: network.INCOMING,
		},
	}

	allAttributes := []attribute.KeyValue{
		attribute.String(SrcIPKey, clientIP.String()),
		attribute.String(DstIPKey, serverIP.String()),
		attribute.String(DstPortKey, fmt.Sprintf("%d", serverPort)),
		attribute.String(SrcPodKey, clientPod.Name),
		attribute.String(SrcNSKey, clientPod.Namespace),
		attribute.String(SrcLabelsKey, clientPod.Labels),
		attribute.String(DstPodKey, serverPod.Name),
		attribute.String(DstNSKey, serverPod.Namespace),
		attribute.String(DstLabelsKey, serverPod.Labels),
	}
	clientAttr := []attribute.KeyValue{
		attribute.String(SrcIPKey, clientIP.String()),
		attribute.String(DstIPKey, serverIP.String()),
		attribute.String(DstPortKey, fmt.Sprintf("%d", serverPort)),
		attribute.String(SrcPodKey, clientPod.Name),
		attribute.String(SrcNSKey, clientPod.Namespace),
		attribute.String(SrcLabelsKey, clientPod.Labels),
	}
	serverAttr := []attribute.KeyValue{
		attribute.String(SrcIPKey, clientIP.String()),
		attribute.String(DstIPKey, serverIP.String()),
		attribute.String(DstPortKey, fmt.Sprintf("%d", serverPort)),
		attribute.String(DstPodKey, serverPod.Name),
		attribute.String(DstNSKey, serverPod.Namespace),
		attribute.String(DstLabelsKey, serverPod.Labels),
	}

	tests := []struct {
		name   string
		conn   network.ConnectionStats
		want   []attribute.KeyValue
		srcPod *kube.PodInfo
		dstPod *kube.PodInfo
	}{
		{
			name:   "outgoing_both_pods",
			conn:   outgoing,
			srcPod: clientPod,
			dstPod: serverPod,
			want:   allAttributes,
		},
		{
			name:   "outgoing_missing_dst_pod_only_client_attrs",
			conn:   outgoing,
			srcPod: clientPod,
			dstPod: nil,
			want:   clientAttr,
		},
		{
			name:   "outgoing_missing_src_pod_only_server_attrs",
			conn:   outgoing,
			srcPod: nil,
			dstPod: serverPod,
			want:   serverAttr,
		},
		{
			name:   "incoming_both_pods",
			conn:   incoming,
			srcPod: serverPod,
			dstPod: clientPod,
			want:   allAttributes,
		},
		{
			name:   "incoming_missing_client_only_server_dst_attrs",
			conn:   incoming,
			srcPod: nil,
			dstPod: clientPod,
			want:   clientAttr,
		},
		{
			name:   "incoming_missing_server_only_client_src_attrs",
			conn:   incoming,
			srcPod: serverPod,
			dstPod: nil,
			want:   serverAttr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getMetricAttributes(&tt.conn, tt.srcPod, tt.dstPod)
			require.Equal(t, tt.want, got)
		})
	}
}
