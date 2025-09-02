package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/sketches-go/ddsketch"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/StackVista/stackstate-process-agent/pkg/kube"
	"github.com/StackVista/stackstate-process-agent/pkg/telemetry"
	log "github.com/cihub/seelog"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/obi/pkg/kubecache/meta"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	// We export them so that we can reuse these fields in e2e tests

	// DirectionKey is the direction of the connection (0=outgoing, 1=incoming)
	DirectionKey = "direction"

	// LOCAL FIELDS

	// LocalIPKey is the IP address of the local pod
	LocalIPKey = "local.ip"
	// LocalPodKey is the name of the local pod
	LocalPodKey = "local.pod"
	// LocalNSKey is the namespace of the local pod
	LocalNSKey = "local.namespace"
	// LocalLabelsKey is the labels of the local pod
	LocalLabelsKey = "local.pod.label"
	// LocalPortKey is the port of the local pod
	LocalPortKey = "local.port"

	// REMOTE FIELDS

	// RemoteIPKey is the IP address of the remote pod
	RemoteIPKey = "remote.ip"
	// RemotePodKey is the name of the remote pod
	RemotePodKey = "remote.pod"
	// RemoteNSKey is the namespace of the remote pod
	RemoteNSKey = "remote.namespace"
	// RemoteLabelsKey is the labels of the remote pod
	RemoteLabelsKey = "remote.pod.label"
	// RemotePortKey is the port of the remote pod
	RemotePortKey = "remote.port"
)

type storedConnection struct {
	conn            *network.ConnectionStats
	protocolMetrics []*model.ConnectionMetric
}

type podCorrelationInfo struct {
	observer                 *kube.Observer
	metadataNotifier         meta.Notifier
	metrics                  *telemetry.MetricsExporter
	exportProtocolMetrics    bool
	exportPartialCorrelation bool
	storedConnections        []*storedConnection
	rootNSIno                uint32
}

func newPodCorrelationInfo(cfg *config.PodCorrelationConfig, logLevel string, rootNSIno uint32) (*podCorrelationInfo, error) {
	podCorrelationInfo := &podCorrelationInfo{
		exportProtocolMetrics:    cfg.ProtocolMetrics,
		exportPartialCorrelation: cfg.PartialCorrelation,
		storedConnections:        make([]*storedConnection, 0),
		rootNSIno:                rootNSIno,
	}

	// if we are in tests we don't want to start the informer
	if cfg.Exporter.Type != config.ExporterTypeManual {
		if err := podCorrelationInfo.startKubernetesInformer(cfg, logLevel); err != nil {
			return nil, err
		}
	}

	var err error
	if podCorrelationInfo.metrics, err = telemetry.NewMetricsExporter(cfg.Exporter); err != nil {
		return nil, err
	}

	return podCorrelationInfo, nil
}

func (pi *podCorrelationInfo) startKubernetesInformer(cfg *config.PodCorrelationConfig, logLevel string) error {
	log.Info("starting kubernetes informer for pod correlated metrics")
	informerCfg := kube.InformerConfig{
		KubeConfigPath: cfg.KubeConfigPath,
		SyncTimeout:    30 * time.Second,
		ResyncPeriod:   5 * time.Minute,
		MetaCacheAddr:  cfg.RemoteCacheAddr,
		LogLevel:       logLevel,
	}

	var err error
	pi.metadataNotifier, err = kube.GetInformer(informerCfg)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes informer: %w", err)
	}
	// if needed we can configure the refresh interval for the deleted pods cache
	pi.observer, err = kube.NewObserver(prometheus.DefaultRegisterer, kube.WithPodDebugEndpoint())
	if err != nil {
		return fmt.Errorf("failed to create kubernetes observer: %w", err)
	}
	pi.metadataNotifier.Subscribe(pi.observer)
	return nil
}

func (pi *podCorrelationInfo) generateConnectionMetrics(conn *network.ConnectionStats, srcPodInfo, dstPodInfo *kube.PodInfo) {
	attrs := attribute.NewSet(getMetricAttributes(conn, srcPodInfo, dstPodInfo)...)

	pi.metrics.BytesRecv.Add(context.Background(), int64(conn.Last.RecvBytes), metric.WithAttributeSet(attrs))
	pi.metrics.BytesSent.Add(context.Background(), int64(conn.Last.SentBytes), metric.WithAttributeSet(attrs))
}

func connectionDirectionToString(direction network.ConnectionDirection) string {
	if direction == network.INCOMING {
		return "incoming"
	}
	return "outgoing"
}

func addPrefixToLabels(prefix string, labels map[string]string) []attribute.KeyValue {
	otelLabels := make([]attribute.KeyValue, 0, len(labels))
	for k, v := range labels {
		otelLabels = append(otelLabels, attribute.String(fmt.Sprintf("%s.%s", prefix, k), v))
	}
	return otelLabels
}

func getMetricAttributes(conn *network.ConnectionStats, localPodInfo, remotePodInfo *kube.PodInfo) []attribute.KeyValue {
	attributes := []attribute.KeyValue{
		attribute.String(LocalIPKey, conn.ConnectionTuple.Source.String()),
		attribute.String(LocalPortKey, fmt.Sprintf("%d", conn.ConnectionTuple.SPort)),
		attribute.String(RemoteIPKey, conn.ConnectionTuple.Dest.String()),
		attribute.String(RemotePortKey, fmt.Sprintf("%d", conn.ConnectionTuple.DPort)),
		attribute.String(DirectionKey, connectionDirectionToString(conn.Direction)),
	}
	if localPodInfo != nil {
		attributes = append(attributes,
			attribute.String(LocalPodKey, localPodInfo.Name),
			attribute.String(LocalNSKey, localPodInfo.Namespace),
		)
		attributes = append(attributes, addPrefixToLabels(LocalLabelsKey, localPodInfo.Labels)...)
	}
	if remotePodInfo != nil {
		attributes = append(attributes,
			attribute.String(RemotePodKey, remotePodInfo.Name),
			attribute.String(RemoteNSKey, remotePodInfo.Namespace),
		)
		attributes = append(attributes, addPrefixToLabels(RemoteLabelsKey, remotePodInfo.Labels)...)
	}
	return attributes
}

func (pi *podCorrelationInfo) generateProtocolMetrics(conn *network.ConnectionStats, srcPodInfo, dstPodInfo *kube.PodInfo, metrics []*model.ConnectionMetric) {
	attr := getMetricAttributes(conn, srcPodInfo, dstPodInfo)

	for _, m := range metrics {
		// todo!: for now we only support postgres metrics.
		if m.Name != string(postgresResponseTime) {
			continue
		}

		postgresSketch, err := ddsketch.FromProto(m.Value.GetHistogram())
		if err != nil || postgresSketch == nil {
			log.Warnf("Failed to parse histogram for metric %s: %v", m.Name, err)
			continue
		}

		// Build merged attributes: base connection attributes + metric-specific tags.
		merged := make([]attribute.KeyValue, 0, len(attr)+len(m.Tags))
		merged = append(merged, attr...)
		for k, v := range m.Tags {
			merged = append(merged, attribute.String(k, v))
		}

		postgresSketch.ForEach(func(value, count float64) (stop bool) {
			for i := 0; i < int(count); i++ {
				// `value` is in seconds
				pi.metrics.PostgresLatency.Record(context.Background(), value, metric.WithAttributes(merged...))
			}
			// False because we want to iterate on all samples.
			return false
		})
	}
}

func (pi *podCorrelationInfo) exportOTELMetrics(conn *network.ConnectionStats, metrics []*model.ConnectionMetric) {
	// 1. Pod -> Pod (INCOMING and OUTGOING)
	// 2. Pod -> Pod HostNetwork (OUTGOING)
	// 3. Pod HostNetwork -> Pod (INCOMING)
	// 4. Pod -> ExternalIP (OUTGOING)
	// 5. ExternalIP -> Pod (INCOMING)
	srcPodInfo, dstPodInfo := pi.observer.ResolvePodsByIPs(conn.ConnectionTuple.Source, conn.ConnectionTuple.Dest, conn.Duration)

	if conn.Direction == network.OUTGOING {
		// We try the resolution
		if dstPodInfo == nil && conn.IPTranslation != nil && conn.IPTranslation.ReplSrcIP.IsValid() {
			dstPodInfo = pi.observer.ResolvePodByIP(conn.IPTranslation.ReplSrcIP, conn.Duration)
			// we need to replace also the remote IP and port from ClusterIP to Pod
			conn.ConnectionTuple.Dest = conn.IPTranslation.ReplSrcIP
			conn.ConnectionTuple.DPort = conn.IPTranslation.ReplSrcPort
		}
	}

	// we can do nothing
	if srcPodInfo == nil && dstPodInfo == nil {
		return
	}

	// if one of the 2 is nil we need to check if we want to export partial correlation
	if (dstPodInfo == nil || srcPodInfo == nil) && !pi.exportPartialCorrelation {
		return
	}

	// For all these cases we want connection and protocol metrics
	// 1. Pod -> Pod (INCOMING)
	// 1. Pod -> Pod (OUTGOING)
	// 2. Pod -> Pod HostNetwork (OUTGOING)
	// 3. Pod HostNetwork -> Pod (INCOMING)
	// 5. Pod -> ExternalIP (OUTGOING)
	// 6. ExternalIP -> Pod (INCOMING)
	pi.generateConnectionMetrics(conn, srcPodInfo, dstPodInfo)
	if pi.exportProtocolMetrics {
		pi.generateProtocolMetrics(conn, srcPodInfo, dstPodInfo, metrics)
	}
}

func (pi *podCorrelationInfo) processConnections(conns []network.ConnectionStats, connectionMetrics map[connKey][]*model.ConnectionMetric) {
	// todo!: this could be done in parallel in the future
	for _, storedConn := range pi.storedConnections {
		pi.exportOTELMetrics(storedConn.conn, storedConn.protocolMetrics)
	}
	// reset the stored connections
	pi.storedConnections = make([]*storedConnection, 0)

	for _, conn := range conns {
		if conn.Type != network.TCP {
			log.Warnf("We should only receive TCP connections here: %v", conn)
			continue
		}

		// Possible cases
		// 1. Pod -> Pod
		// 2. Pod -> Pod HostNetwork == Pod -> Host
		// 3. Pod HostNetwork -> Pod == Host -> Pod
		// 4. Pod HostNetwork -> Pod HostNetwork == Host -> Host
		// 5. Pod -> ExternalIP
		// 6. ExternalIP -> Pod
		// ...Service meshes not considered for now.
		//
		// Let's take the simple case of a pod connecting to another pod P1 -> P2 (both are in their own netns)
		// For this TCP connection we will receive 2 different `conn` here.
		// OUTGOING: P1(SRC) -> P2(DST) (netns of the client because we catch the connect ebpf side)
		// INCOMING: P2(SRC) <- P1(DST) (netns of the server because we catch the accept ebpf side)
		//
		// For connection metrics is enough to catch one of the 2 sides.
		// For protocol metrics we probably want to catch them both to have metrics on the client side and metrics on the server side.
		//
		// As a first optimization we decide to filter all connections (OUTGOING/INCOMING) that belongs to the root network namespace.
		// This will allow us to catch only connections when at least one pod (not in hostNetwork) is involved.
		//
		// 1. Pod -> Pod (we keep both INCOMING and OUTGOING)
		// 2. Pod -> Pod HostNetwork (we keep only the OUTGOING, the incoming will be in the root netns)
		// 3. Pod HostNetwork -> Pod (we keep only the INCOMING, the outgoing will be in the root netns)
		// 4. Pod HostNetwork -> Pod HostNetwork (we discard both, this should be fine since in any case we cannot resolve the pod info for pod in hostNetwork)
		// 5. Pod -> ExternalIP (we will receive only OUTGOING and we keep it)
		// 6. ExternalIP -> Pod (we will receive only INCOMING and we keep it)
		if conn.ConnectionTuple.NetNS == pi.rootNSIno {
			continue
		}

		// We should always have the right direction
		if conn.Direction != network.OUTGOING && conn.Direction != network.INCOMING {
			log.Warnf("Skipping connection %v with direction %s", conn, conn.Direction)
			return
		}

		protocolMetrics := make([]*model.ConnectionMetric, 0)

		// Example:
		// conn.ConnectionTuple -> INCOMING src: 10.42.0.9:5432, dst: 10.42.0.10:48616 (server netns: 4026533741)
		// metric.key -> src: 10.42.0.10:48616, dst: 10.42.0.9:5432 (server netns: 4026533741) -> the tuple in metrics is always normalized (client->server)
		// so we need to normalize the connection tuple
		normalizedKey := getNormalizedConnKey(&conn)
		if len(connectionMetrics[normalizedKey]) > 0 {
			protocolMetrics = append(protocolMetrics, connectionMetrics[normalizedKey]...)
			log.Debugf("Found match between metric and connection with key: %v", normalizedKey)
		}

		// If the connection is too young we store it with its metrics and we will try to correlate it later
		if pi.observer.ConnectionNeedsRetry(conn.Duration) {
			pi.storedConnections = append(pi.storedConnections, &storedConnection{
				conn:            &conn,
				protocolMetrics: protocolMetrics,
			})
			continue
		}

		pi.exportOTELMetrics(&conn, protocolMetrics)
	}
}

func getNormalizedConnKey(conn *network.ConnectionStats) connKey {
	// If outgoing we have to do nothing
	saddr := conn.Source
	sport := conn.SPort
	daddr := conn.Dest
	dport := conn.DPort

	if conn.Direction == network.INCOMING {
		saddr = conn.Dest
		sport = conn.DPort
		daddr = conn.Source
		dport = conn.SPort
	}

	saddrl, saddrh := util.ToLowHigh(saddr)
	daddrl, daddrh := util.ToLowHigh(daddr)
	return connKey{
		SrcIPHigh: saddrh,
		SrcIPLow:  saddrl,
		SrcPort:   sport,
		DstIPHigh: daddrh,
		DstIPLow:  daddrl,
		DstPort:   dport,
		NetNs:     conn.NetNS,
	}
}
