package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/DataDog/datadog-agent/pkg/network"
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
	// SRC FIELDS
	srcIP     = "src.ip"
	srcPod    = "src.pod"
	srcNS     = "src.namespace"
	srcLabels = "src.labels"

	// DST FIELDS
	dstIP     = "dst.ip"
	dstPod    = "dst.pod"
	dstNS     = "dst.namespace"
	dstLabels = "dst.labels"
	dstPort   = "dst.port"
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
}

func newPodCorrelationInfo(cfg *config.PodCorrelationConfig, logLevel string) (*podCorrelationInfo, error) {

	podCorrelationInfo := &podCorrelationInfo{
		exportProtocolMetrics:    cfg.ExportProtocolMetrics,
		exportPartialCorrelation: cfg.ExportPartialCorrelation,
		storedConnections:        make([]*storedConnection, 0),
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
		MetaCacheAddr:  cfg.RemoteKubeCacheAddr,
		LogLevel:       logLevel,
	}

	var err error
	pi.metadataNotifier, err = kube.GetInformer(informerCfg)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes informer: %w", err)
	}
	// if needed we can configure the refresh interval for the deleted pods cache
	pi.observer, err = kube.NewObserver(prometheus.DefaultRegisterer)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes observer: %w", err)
	}
	pi.metadataNotifier.Subscribe(pi.observer)
	return nil
}

func (pi *podCorrelationInfo) generateConnectionMetrics(conn *network.ConnectionStats, srcPodInfo, dstPodInfo *kube.PodInfo) {
	attrs := attribute.NewSet(
		attribute.String(srcIP, conn.ConnectionTuple.Source.String()),
		attribute.String(srcPod, srcPodInfo.Name),
		attribute.String(srcNS, srcPodInfo.Namespace),
		attribute.String(srcLabels, srcPodInfo.LabelsString()),

		attribute.String(dstIP, conn.ConnectionTuple.Dest.String()),
		attribute.String(dstPod, dstPodInfo.Name),
		attribute.String(dstNS, dstPodInfo.Namespace),
		attribute.String(dstLabels, dstPodInfo.LabelsString()),
		attribute.String(dstPort, fmt.Sprintf("%d", conn.ConnectionTuple.DPort)),
	)
	// We always call this method with `conn.Direction == network.INCOMING` so we want to invert the sent/received bytes
	pi.metrics.BytesRecv.Add(context.Background(), int64(conn.Last.SentBytes), metric.WithAttributeSet(attrs))
	pi.metrics.BytesSent.Add(context.Background(), int64(conn.Last.RecvBytes), metric.WithAttributeSet(attrs))
}

func (pi *podCorrelationInfo) generateProtocolMetrics(conn *network.ConnectionStats, srcPodInfo, dstPodInfo *kube.PodInfo, metrics []*model.ConnectionMetric) {
	// TODO!: Generate metrics for protocols
}

func (pi *podCorrelationInfo) exportOTELMetrics(conn *network.ConnectionStats, metrics []*model.ConnectionMetric) {
	srcPodInfo, dstPodInfo := pi.observer.ResolvePodsByIPs(conn.ConnectionTuple.Source, conn.ConnectionTuple.Dest, conn.Duration)

	// if we don't want to export protocol metrics the incoming connections are enough.
	// Here we should already have the resolved IPs (ClusterIP->PodIP)
	if conn.Direction == network.INCOMING {
		// in the incoming case the srcPod is the pod the accepted the connection (usually the server)
		if srcPodInfo == nil {
			// this is not a communication a pod <-> pod communication, the src should be always be a pod IP
			return
		}

		if dstPodInfo == nil && !pi.exportPartialCorrelation {
			return
		}
		// the dstPod is the one that started the connection (with `connect` syscall)
		// So we invert the src/dst
		pi.generateConnectionMetrics(conn, dstPodInfo, srcPodInfo)
	}

	if !pi.exportProtocolMetrics {
		return
	}

	// if the connection is incoming we already have the srcPod/dstPod
	// we can directly call the generateProtocolMetrics

	if conn.Direction == network.INCOMING {
		pi.generateProtocolMetrics(conn, srcPodInfo, dstPodInfo, metrics)
		return
	}

	if conn.Direction != network.OUTGOING {
		log.Warnf("Skipping connection %v with direction %s", conn, conn.Direction)
		return
	}

	// We are in the outgoing case
	if srcPodInfo == nil {
		// this is not a communication a pod <-> pod communication, the source should be always be a pod IP
		return
	}

	if dstPodInfo == nil {
		// it could be the destination is a ClusterIP, so we try the resolution.
		if conn.IPTranslation != nil && conn.IPTranslation.ReplSrcIP.IsValid() {
			dstPodInfo = pi.observer.ResolvePodByIP(conn.IPTranslation.ReplSrcIP, conn.Duration)
		}
		// if we cannot determine the pod we cannot say much about the connection...
		if dstPodInfo == nil && !pi.exportPartialCorrelation {
			return
		}
	}
	pi.generateProtocolMetrics(conn, srcPodInfo, dstPodInfo, metrics)
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

		protocolMetrics := make([]*model.ConnectionMetric, 0)

		// Try to recover all metrics associated with this connection.
		for _, co := range getConnectionKeys(conn) {
			protocolMetrics = append(protocolMetrics, connectionMetrics[co]...)
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
