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
	processAgentLabels   = "app.kubernetes.io/component=node-agent"
	prometheusLabels     = "app.kubernetes.io/name=prometheus"
	otelCollectorLabels  = "app.kubernetes.io/name=opentelemetry-collector"
	postgresClientLabels = "app.kubernetes.io/name=postgres-client"
	postgresServerLabels = "app.kubernetes.io/name=postgres-server"

	prometheusServiceName = "prometheus-server"
	prometheusPortName    = "http"

	namespace = "default"

	postgresSQLCommandTag   = "command"
	postgresDatabaseNameTag = "database"
	postgresTableNameTag    = "table"

	outgoingDir = "outgoing"
	incomingDir = "incoming"

	telemetryNs = "open-telemetry"
	defaultNs   = "default"
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

func isAttributeRequired(requiredAttrsKeys []string, key string) bool {
	// some attributes like labels are already in the form local.pod.labels.<label_key> so a simple contains is not enough, we need to check the prefix
	for _, allowedKey := range requiredAttrsKeys {
		if key == allowedKey || strings.HasPrefix(key, allowedKey+".") {
			return true
		}
	}
	return false
}

func composePromQuery(otelMetric string, direction string, localAttrs, remoteAttrs, extraAttrs map[string]string, requiredAttrsKeys []string) string {
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
	promMetric += fmt.Sprintf(`{`)
	if isAttributeRequired(requiredAttrsKeys, checks.DirectionKey) {
		promMetric += fmt.Sprintf(`%s="%s",`, checks.DirectionKey, direction)
	}
	for k, v := range remoteAttrs {
		if !isAttributeRequired(requiredAttrsKeys, k) {
			continue
		}
		promMetric += fmt.Sprintf(`%s="%s",`, nonAlphanumericRegex.ReplaceAllString(k, "_"), v)
	}
	for k, v := range localAttrs {
		if !isAttributeRequired(requiredAttrsKeys, k) {
			continue
		}
		promMetric += fmt.Sprintf(`%s="%s",`, nonAlphanumericRegex.ReplaceAllString(changeRemoteKeyIntoLocalKey(k), "_"), v)
	}
	// if we specify extra attributes, we assume they are all required
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

func getPodAttributes(t *testing.T, client *kubernetes.Clientset, podLabel string, ns string) map[string]string {
	var pod corev1.Pod
	require.Eventually(t, func() bool {
		pods, err := client.CoreV1().Pods(ns).List(t.Context(), metav1.ListOptions{LabelSelector: podLabel})
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
		checks.RemotePodNameKey: pod.Name,
		checks.RemoteNSKey:      pod.Namespace,
		checks.RemoteIPKey:      pod.Status.PodIP,
	}

	for k, v := range pod.Labels {
		// We will convert to prometheus format later
		attrs[checks.RemoteLabelsKey+"."+k] = v
	}

	return attrs
}

func getProcessAgentMetricsAttributes(t *testing.T, client *kubernetes.Clientset) []string {
	var pod corev1.Pod
	require.Eventually(t, func() bool {
		pods, err := client.CoreV1().Pods("").List(t.Context(), metav1.ListOptions{LabelSelector: processAgentLabels})
		if err != nil {
			t.Logf("cannot find pod with label %s: %v", processAgentLabels, err)
			return false
		}

		// We expect one pod with the given label
		if len(pods.Items) != 1 {
			t.Logf("expected one pod for label %s, got %d", processAgentLabels, len(pods.Items))
			return false
		}
		pod = pods.Items[0]
		return true
	}, 30*time.Second, 500*time.Millisecond, "failed to find pod with label "+processAgentLabels)

	// We check the process-agent is present
	require.Len(t, pod.Spec.Containers, 2, "expected 2 containers in the process agent pod")
	var container corev1.Container
	for _, cont := range pod.Spec.Containers {
		if cont.Name == "process-agent" {
			container = cont
			break
		}
	}
	require.NotEqual(t, container.Name, "")

	attrs := []string{}
	for _, env := range container.Env {
		if env.Name != "STS_POD_CORRELATION_ATTRIBUTES_KEYS" {
			continue
		}
		if env.Value == "" {
			attrs = checks.DefaultAttributeKeys
			break
		} else {
			attrs = strings.Split(env.Value, ",")
			break
		}
	}

	require.NotEqual(t, 0, len(attrs), "no pod correlation attributes found in process-agent pod")
	return attrs
}

func TestBasicOTELMetrics(t *testing.T) {
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
	// Get attributes keys from process-agent pod
	//////////////////////
	attributeKeys := getProcessAgentMetricsAttributes(t, client)

	//////////////////////
	// Create prometheus client
	//////////////////////
	pq := Client{HostPort: fmt.Sprintf("%s:%d", nodeIp, nodePort)}

	//////////////////////
	// Get all pods info
	//////////////////////
	otelCollectorAttrs := getPodAttributes(t, client, otelCollectorLabels, telemetryNs)
	prometheusAttrs := getPodAttributes(t, client, prometheusLabels, telemetryNs)
	postgresClientAttrs := getPodAttributes(t, client, postgresClientLabels, defaultNs)
	postgresServerAttrs := getPodAttributes(t, client, postgresServerLabels, defaultNs)

	extraPostgresAttrs := map[string]string{
		postgresSQLCommandTag: "SELECT",
		// the database name could be there or not, it really depends on the timing of when the process-agent is deployed
		postgresTableNameTag: "demo",
	}

	tests := []struct {
		name        string
		metricName  string
		localAttrs  map[string]string
		remoteAttrs map[string]string
		extraAttrs  map[string]string
	}{
		{
			// prometheus scrapes data from the OTEL collector (we want to see both OUTGOING and INCOMING direction)
			// here we populate the data for the outgoing direction, the test will switch them for the incoming case
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
			query := composePromQuery(tt.metricName, outgoingDir, tt.localAttrs, tt.remoteAttrs, tt.extraAttrs, attributeKeys)
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
			query := composePromQuery(tt.metricName, incomingDir, tt.remoteAttrs, tt.localAttrs, tt.extraAttrs, attributeKeys)
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
