//go:build test

package checks

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/StackVista/stackstate-process-agent/pkg/kube"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestPodCorrelation(t *testing.T) {
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
			util.AddressFromString("10.244.0.2"): {&kube.PodInfo{
				Namespace:         "default",
				Name:              "postgres-client",
				Labels:            map[string]string{"app": "client"},
				CreationTimestamp: 40,
				DeletionTimestamp: 0,
			}},
			util.AddressFromString("10.244.0.3"): {&kube.PodInfo{
				Namespace:         "default",
				Name:              "postgres-server",
				Labels:            map[string]string{"app": "server"},
				CreationTimestamp: 41,
				DeletionTimestamp: 0,
			}},
		}))
	require.NoError(t, err)

	///////////////////////////
	// Create a pod correlation info struct with a manual exporter
	///////////////////////////
	pi, err := newPodCorrelationInfo(&config.PodCorrelationConfig{
		Enabled:                  true,
		ExportProtocolMetrics:    false,
		ExportPartialCorrelation: false,
		Exporter: config.ExporterConfig{
			Type: config.ExporterTypeManual,
		},
	}, "DEBUG")
	require.NoError(t, err)

	// Overwrite the observer in the pod correlation struct
	pi.observer = obs

	// Build one INCOMING TCP connection from client pod to server pod
	conn := network.ConnectionStats{
		ConnectionTuple: network.ConnectionTuple{
			Type:      network.TCP,
			Family:    network.AFINET,
			Direction: network.INCOMING,
			Source:    util.AddressFromString("10.244.0.2"), // client pod
			Dest:      util.AddressFromString("10.244.0.3"), // server pod
			SPort:     54321,
			DPort:     5432,
		},
		Duration: 10 * time.Second,
		Last: network.StatCounters{
			RecvBytes: 111,
			SentBytes: 222,
		},
	}

	conns := []network.ConnectionStats{conn}
	connectionMetrics := make(map[connKey][]*model.ConnectionMetric)

	// Process and export metrics
	pi.processConnections(conns, connectionMetrics)

	// Collect from ManualReader
	var rm metricdata.ResourceMetrics
	require.NoError(t, pi.metrics.Reader.Collect(context.Background(), &rm))
	fmt.Println(rm)

	// Find our two counters and assert values and attributes
	// Helper to flatten datapoints
	getAttr := func(set attribute.Set, key string) (string, bool) {
		if v, ok := set.Value(attribute.Key(key)); ok {
			return v.AsString(), true
		}
		return "", false
	}

	var gotSent, gotRecv bool
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				switch m.Name {
				case "agent.network.sent":
					require.Len(t, data.DataPoints, 1)
					dp := data.DataPoints[0]
					require.Equal(t, int64(222), dp.Value)
					srcIP, _ := getAttr(dp.Attributes, "src.ip")
					srcPod, _ := getAttr(dp.Attributes, "src.pod")
					dstIP, _ := getAttr(dp.Attributes, "dst.ip")
					dstPod, _ := getAttr(dp.Attributes, "dst.pod")
					require.Equal(t, "10.244.0.2", srcIP)
					require.Equal(t, "postgres-client", srcPod)
					require.Equal(t, "10.244.0.3", dstIP)
					require.Equal(t, "postgres-server", dstPod)
					gotSent = true
				case "agent.network.received":
					require.Len(t, data.DataPoints, 1)
					dp := data.DataPoints[0]
					require.Equal(t, int64(111), dp.Value)
					srcIP, _ := getAttr(dp.Attributes, "src.ip")
					srcPod, _ := getAttr(dp.Attributes, "src.pod")
					dstIP, _ := getAttr(dp.Attributes, "dst.ip")
					dstPod, _ := getAttr(dp.Attributes, "dst.pod")
					require.Equal(t, "10.244.0.2", srcIP)
					require.Equal(t, "postgres-client", srcPod)
					require.Equal(t, "10.244.0.3", dstIP)
					require.Equal(t, "postgres-server", dstPod)
					gotRecv = true
				}
			}
		}
	}
	require.True(t, gotSent, "agent.network.sent not found")
	require.True(t, gotRecv, "agent.network.received not found")
}

// TODO!: Add tests for stored connections
// TODO!: Add tests with protocol metrics
// TODO!: Add tests with partial correlation
// TODO!: Add test with clusterIP translation
