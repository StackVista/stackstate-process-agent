//go:build k8s_e2e

package otel_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/StackVista/stackstate-process-agent/checks"
	"github.com/StackVista/stackstate-process-agent/pkg/telemetry"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	processAgentLabels   = "app=process-agent"
	prometheusLabels     = "app.kubernetes.io/name=prometheus"
	testserverLabels     = "app=test-server"
	otelCollectorLabels  = "app=opentelemetry"
	postgresClientLabels = "app=postgres-client"
	postgresServerLabels = "app=postgres-server"

	prometheusServiceName = "prometheus-service"
	prometheusPortName    = "web"

	namespace = "default"

	postgresSQLCommandTag   = "command"
	postgresDatabaseNameTag = "database"
	postgresTableNameTag    = "table"

	outgoingDir = "outgoing"
	incomingDir = "incoming"
)

var nonAlphanumericRegex = regexp.MustCompile(`[^a-zA-Z0-9]`)

type queryResult struct {
	Status string `json:"status"`
	Data   data   `json:"data"`
}

type data struct {
	Result     []Result `json:"result"`
	ResultType string   `json:"resultType"`
}

// Result structure assumes that resultType is always == "vector"
// Result example:
// Metric: map[__name__:agent_network_sent_bytes_total dst_ip:10.244.0.6 dst_labels:[app=opentelemetry component=collector pod-template-hash=6d8b797668] dst_namespace:default dst_pod:otel-collector-deployment-6d8b797668-qpmvr dst_port:9464 exported_job:process-agent instance:otel-collector-service.default.svc.cluster.local:9464 job:otel-collector otel_scope_name:network src_ip:10.244.0.7 src_labels:[app.kubernetes.io/name=prometheus pod-template-hash=779c4f5c8f] src_namespace:default src_pod:prometheus-779c4f5c8f-tm67k]
// Value: [1.756113295485e+09 282940]
type Result struct {
	Metric map[string]string `json:"metric"`
	Value  []any
}

type Client struct {
	HostPort string
}

func (c *Client) Query(t *testing.T, promQL string) ([]Result, error) {
	qurl := "http://" + c.HostPort + "/api/v1/query?query=" + url.PathEscape(promQL)
	t.Logf("querying prometheus. query: %s", promQL)
	resp, err := http.Get(qurl)
	if err != nil {
		return nil, fmt.Errorf("querying prometheus: %w", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("can't read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prometheus returned status %q", resp.Status)
	}
	qr := queryResult{}
	if err := json.Unmarshal(body, &qr); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	t.Log("prometheus query successful")
	return qr.Data.Result, nil
}

func buildClient() (*kubernetes.Clientset, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return kubernetes.NewForConfig(cfg)
	}
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = os.ExpandEnv("$HOME/.kube/config")
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}

func convertOtelMetricToProm(otelName string, suffix string) string {
	// Example: "agent.network.sent" -> "agent_network_sent"
	return strings.ReplaceAll(otelName, ".", "_") + "_" + suffix
}

func changeRemoteKeyIntoLocalKey(key string) string {
	if strings.HasPrefix(key, "remote.") {
		return "local." + strings.TrimPrefix(key, "remote.")
	}
	panic("unexpected non-remote key: " + key)
}

func composePromQuery(otelMetric string, direction string, localAttrs, remoteAttrs, extraAttrs map[string]string) string {
	promMetric := ""
	switch otelMetric {
	case telemetry.SentMetricName:
		promMetric = convertOtelMetricToProm(telemetry.SentMetricName, "bytes_total")
	case telemetry.ReceivedMetricName:
		promMetric = convertOtelMetricToProm(telemetry.ReceivedMetricName, "bytes_total")
	case telemetry.PostgresLatencyName:
		promMetric = convertOtelMetricToProm(telemetry.PostgresLatencyName, "seconds_count")
	default:
		panic("unsupported otel metric: " + otelMetric)
	}

	promMetric += fmt.Sprintf(`{%s="%s",`, checks.DirectionKey, direction)
	for k, v := range remoteAttrs {
		promMetric += fmt.Sprintf(`%s="%s",`, nonAlphanumericRegex.ReplaceAllString(k, "_"), v)
	}
	for k, v := range localAttrs {
		promMetric += fmt.Sprintf(`%s="%s",`, nonAlphanumericRegex.ReplaceAllString(changeRemoteKeyIntoLocalKey(k), "_"), v)
	}
	// not always present
	for k, v := range extraAttrs {
		promMetric += fmt.Sprintf(`%s="%s",`, nonAlphanumericRegex.ReplaceAllString(k, "_"), v)
	}
	promMetric = strings.TrimSuffix(promMetric, ",") + "}"
	return promMetric
}

func getPrometheusNodePort(ctx context.Context, client *kubernetes.Clientset) (int32, error) {
	// iterate namespaces (simple approach)
	svcs, err := client.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, err
	}
	for _, s := range svcs.Items {
		if s.Name != prometheusServiceName {
			continue
		}
		for _, p := range s.Spec.Ports {
			if p.Name == prometheusPortName {
				return p.NodePort, nil
			}
		}
	}
	return 0, fmt.Errorf("prometheus service %q not found", prometheusServiceName)
}

func getNodeIP(ctx context.Context, client *kubernetes.Clientset) (string, error) {
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", err
	}
	for _, n := range nodes.Items {
		for _, addr := range n.Status.Addresses {
			// we take the first one, it should be ok
			if addr.Type == corev1.NodeInternalIP {
				return addr.Address, nil
			}
		}
	}
	return "", fmt.Errorf("no node internal IP found")
}

func stringifyPodLabels(labels map[string]string) string {
	labelsStr := make([]string, 0, len(labels))
	for k, v := range labels {
		labelsStr = append(labelsStr, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(labelsStr)
	return fmt.Sprintf("%v", labelsStr)
}

func getPodAttributes(t *testing.T, client *kubernetes.Clientset, podLabel string) map[string]string {
	var pod corev1.Pod
	require.Eventually(t, func() bool {
		pods, err := client.CoreV1().Pods(namespace).List(t.Context(), metav1.ListOptions{LabelSelector: podLabel})
		if err != nil {
			t.Logf("cannot find pod with label %s: %v", podLabel, err)
			return false
		}

		// We expect one pod with the given label
		if len(pods.Items) != 1 {
			t.Logf("expected one pod for label %s, got %d", podLabel, len(pods.Items))
			return false
		}
		pod = pods.Items[0]
		return true
	}, 30*time.Second, 500*time.Millisecond, "failed to find pod with label "+podLabel)

	attrs := map[string]string{
		// we choose dst keys but we will change them to source if the the pod will be used as source
		checks.RemotePodKey: pod.Name,
		checks.RemoteNSKey:  pod.Namespace,
		checks.RemoteIPKey:  pod.Status.PodIP,
	}

	for k, v := range pod.Labels {
		// We will convert to prometheus format later
		attrs[checks.RemoteLabelsKey+"."+k] = v
	}

	return attrs
}

func TestOTELMetricsE2E(t *testing.T) {
	//////////////////////
	// Create k8s client
	//////////////////////
	client, err := buildClient()
	if err != nil {
		t.Fatal(err)
	}

	//////////////////////
	// Get node port and IP to contact prometheus
	//////////////////////
	var nodePort int32
	var nodeIp string
	require.Eventually(t, func() bool {
		var err error
		nodePort, err = getPrometheusNodePort(t.Context(), client)
		if err != nil {
			t.Logf("error finding prometheus service: %v", err)
			return false
		}
		nodeIp, err = getNodeIP(t.Context(), client)
		if err != nil {
			t.Logf("error finding node IP: %v", err)
			return false
		}
		return true
	}, 30*time.Second, 500*time.Millisecond, "waiting for metrics to be available")

	//////////////////////
	// Create prometheus client
	//////////////////////
	pq := Client{HostPort: fmt.Sprintf("%s:%d", nodeIp, nodePort)}

	//////////////////////
	// Get all pods info
	//////////////////////
	processAgentAttrs := getPodAttributes(t, client, processAgentLabels)
	otelCollectorAttrs := getPodAttributes(t, client, otelCollectorLabels)
	testserverAttrs := getPodAttributes(t, client, testserverLabels)
	prometheusAttrs := getPodAttributes(t, client, prometheusLabels)
	postgresClientAttrs := getPodAttributes(t, client, postgresClientLabels)
	postgresServerAttrs := getPodAttributes(t, client, postgresServerLabels)

	extraPostgresAttrs := map[string]string{
		postgresSQLCommandTag:   "SELECT",
		postgresDatabaseNameTag: "<unobserved>",
		postgresTableNameTag:    "demo",
	}

	tests := []struct {
		name        string
		metricName  string
		localAttrs  map[string]string
		remoteAttrs map[string]string
		extraAttrs  map[string]string
	}{
		{
			// process agent sends data to the test server (we want to see both OUTGOING and INCOMING direction)
			// here we populate the data for the outgoing direction, the test will switch them for the incoming case
			name:        "process-agent<->test-server_sent",
			metricName:  telemetry.SentMetricName,
			localAttrs:  processAgentAttrs,
			remoteAttrs: testserverAttrs,
			extraAttrs:  nil,
		},
		{
			name:        "process-agent<->test-server_received",
			metricName:  telemetry.ReceivedMetricName,
			localAttrs:  processAgentAttrs,
			remoteAttrs: testserverAttrs,
		},
		{
			// prometheus scrapes data from the process agent
			name:        "prometheus<->process-agent_sent",
			metricName:  telemetry.SentMetricName,
			localAttrs:  prometheusAttrs,
			remoteAttrs: processAgentAttrs,
		},
		{
			name:        "prometheus<->process-agent_received",
			metricName:  telemetry.ReceivedMetricName,
			localAttrs:  prometheusAttrs,
			remoteAttrs: processAgentAttrs,
		},
		{
			// prometheus scrapes data from the OTEL collector
			name:        "prometheus<->otel_sent",
			metricName:  telemetry.SentMetricName,
			localAttrs:  prometheusAttrs,
			remoteAttrs: otelCollectorAttrs,
		},
		{
			name:        "prometheus<->otel_received",
			metricName:  telemetry.ReceivedMetricName,
			localAttrs:  prometheusAttrs,
			remoteAttrs: otelCollectorAttrs,
		},
		{
			// agent sends telemetry data to the OTEL collector
			name:        "process-agent<->otel_sent",
			metricName:  telemetry.SentMetricName,
			localAttrs:  processAgentAttrs,
			remoteAttrs: otelCollectorAttrs,
		},
		{
			name:        "process-agent<->otel_received",
			metricName:  telemetry.ReceivedMetricName,
			localAttrs:  processAgentAttrs,
			remoteAttrs: otelCollectorAttrs,
		},
		{
			name:        "postgres-client<->postgres-server_sent",
			metricName:  telemetry.SentMetricName,
			localAttrs:  postgresClientAttrs,
			remoteAttrs: postgresServerAttrs,
		},
		{
			name:        "postgres-client<->postgres-server_received",
			metricName:  telemetry.ReceivedMetricName,
			localAttrs:  postgresClientAttrs,
			remoteAttrs: postgresServerAttrs,
		},
		{
			name:        "postgres-client<->postgres-server_latency",
			metricName:  telemetry.PostgresLatencyName,
			localAttrs:  postgresClientAttrs,
			remoteAttrs: postgresServerAttrs,
			extraAttrs:  extraPostgresAttrs,
		},
	}

	for _, tt := range tests {
		// Outgoing case
		t.Run(tt.name+"_outgoing", func(t *testing.T) {
			query := composePromQuery(tt.metricName, outgoingDir, tt.localAttrs, tt.remoteAttrs, tt.extraAttrs)
			require.Eventually(t, func() bool {
				results, err := pq.Query(t, query)
				if err != nil {
					t.Logf("error querying prometheus: %v", err)
					return false
				}
				// in today tests we expect just one metric
				if len(results) != 1 {
					t.Logf("unexpected number of results: %d", len(results))
					return false
				}
				return true
			}, 20*time.Second, 500*time.Millisecond, "waiting for metrics to be available")
		})

		// Incoming case
		t.Run(tt.name+"_incoming", func(t *testing.T) {
			query := composePromQuery(tt.metricName, incomingDir, tt.remoteAttrs, tt.localAttrs, tt.extraAttrs)
			require.Eventually(t, func() bool {
				results, err := pq.Query(t, query)
				if err != nil {
					t.Logf("error querying prometheus: %v", err)
					return false
				}
				// in today tests we expect just one metric
				if len(results) != 1 {
					t.Logf("unexpected number of results: %d", len(results))
					return false
				}
				return true
			}, 20*time.Second, 500*time.Millisecond, "waiting for metrics to be available")
		})
	}
}
