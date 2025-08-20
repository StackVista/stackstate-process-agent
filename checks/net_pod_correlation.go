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
	srcIPKey     = "src.ip"
	srcPodKey    = "src.pod"
	srcNSKey     = "src.namespace"
	srcLabelsKey = "src.labels"

	// DST FIELDS
	dstIPKey     = "dst.ip"
	dstPodKey    = "dst.pod"
	dstNSKey     = "dst.namespace"
	dstLabelsKey = "dst.labels"
	dstPortKey   = "dst.port"
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
	// Today here we always receive INCOMING connections.
	// the srcIP, srcPort, srcPodInfo are all relative to the server.
	// we want to obtain a metric client -> server so we need to invert the src/dst

	// in case of partial correlation `srcPodInfo` and `dstPodInfo` can be nil so we need to handle these cases.
	// we always populate only the information we can recover from the tuple.
	kvs := []attribute.KeyValue{
		attribute.String(srcIPKey, conn.ConnectionTuple.Dest.String()),
		attribute.String(dstIPKey, conn.ConnectionTuple.Source.String()),
		attribute.String(dstPortKey, fmt.Sprintf("%d", conn.ConnectionTuple.SPort)),
	}
	if dstPodInfo != nil {
		kvs = append(kvs,
			attribute.String(srcPodKey, dstPodInfo.Name),
			attribute.String(srcNSKey, dstPodInfo.Namespace),
			attribute.String(srcLabelsKey, dstPodInfo.Labels),
		)
	}
	if srcPodInfo != nil {
		kvs = append(kvs,
			attribute.String(dstPodKey, srcPodInfo.Name),
			attribute.String(dstNSKey, srcPodInfo.Namespace),
			attribute.String(dstLabelsKey, srcPodInfo.Labels),
		)
	}

	attrs := attribute.NewSet(kvs...)

	// We want to invert the sent/received bytes to obtain the effect client -> server
	pi.metrics.BytesRecv.Add(context.Background(), int64(conn.Last.SentBytes), metric.WithAttributeSet(attrs))
	pi.metrics.BytesSent.Add(context.Background(), int64(conn.Last.RecvBytes), metric.WithAttributeSet(attrs))
}

func (pi *podCorrelationInfo) generateProtocolMetrics(conn *network.ConnectionStats, srcPodInfo, dstPodInfo *kube.PodInfo, metrics []*model.ConnectionMetric) {
	// TODO!: Generate metrics for protocols
}

func (pi *podCorrelationInfo) exportOTELMetrics(conn *network.ConnectionStats, metrics []*model.ConnectionMetric) {
	srcPodInfo, dstPodInfo := pi.observer.ResolvePodsByIPs(conn.ConnectionTuple.Source, conn.ConnectionTuple.Dest, conn.Duration)

	// this is probably not a pod <-> pod communication, we can return
	if srcPodInfo == nil && dstPodInfo == nil {
		return
	}

	// if we don't want to export protocol metrics the incoming connections are enough.
	// Here we should already have the resolved IPs (ClusterIP->PodIP)
	// At least 3 cases:
	// 1. pod <-> pod (always exported)
	// 2. pod -> host (exported if partial correlation is enabled). There are no clusterIp in the middle so no issues in the resolution.
	// 3. host -> pod (exported if partial correlation is enabled). The host could use a clusterIP to reach the pod but this is resolved on the destination.
	if conn.Direction == network.INCOMING {
		// if one of the 2 is nil we need to check if we want to export partial correlation
		if (dstPodInfo == nil || srcPodInfo == nil) && !pi.exportPartialCorrelation {
			return
		}
		pi.generateConnectionMetrics(conn, srcPodInfo, dstPodInfo)
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
