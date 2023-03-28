package checks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/network/dns"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/http"
	"github.com/DataDog/datadog-agent/pkg/network/tracer"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/kubelet"
	"github.com/StackVista/stackstate-process-agent/pkg/pods"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/model/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"sync"

	"strings"
	"time"

	"github.com/DataDog/sketches-go/ddsketch"

	"github.com/StackVista/stackstate-process-agent/cmd/agent/features"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	log "github.com/cihub/seelog"
)

var (
	// Connections is a singleton ConnectionsCheck.
	Connections = &ConnectionsCheck{}

	// ErrTracerStillNotInitialized signals that the tracer is _still_ not ready, so we shouldn't log additional errors
	ErrTracerStillNotInitialized = errors.New("remote tracer is still not initialized")
)

// ConnectionsCheck collects statistics about live TCP and UDP connections.
type ConnectionsCheck struct {
	// Local network tracer
	useLocalTracer bool
	localTracer    *tracer.Tracer
	localTracerErr error

	podsCache *pods.CachedPods

	prevCheckTime time.Time

	buf *bytes.Buffer // Internal buffer

	// Use this as the network relation cache to calculate rate metrics and drop short-lived network relations
	cache *NetworkRelationCache
}

// Name returns the name of the ConnectionsCheck.
func (c *ConnectionsCheck) Name() string { return "connections" }

// Endpoint returns the endpoint where this check is submitted.
func (c *ConnectionsCheck) Endpoint() string { return "/api/v1/connections" }

// Run runs the ConnectionsCheck to collect the live TCP connections on the
// system. Currently only linux systems are supported as eBPF is used to gather
// this information. For each connection we'll return a `model.Connection`
// that will be bundled up into a `CollectorConnections`.
// See agent.proto for the schema of the message and models.
func (c *ConnectionsCheck) Run(cfg *config.AgentConfig, _ features.Features, groupID int32, currentTime time.Time) (*CheckResult, error) {
	// If local tracer failed to initialize, so we shouldn't be doing any checks
	if c.useLocalTracer && c.localTracer == nil {
		log.Errorf("failed to create network tracer. Set the environment STS_NETWORK_TRACING_ENABLED to false to disable network connections reporting")
		return nil, c.localTracerErr
	}

	start := time.Now()

	conns, err := c.getConnections()
	if err != nil {
		// If the tracer is not initialized, or still not initialized, then we want to exit without error'ing
		if err == ebpf.ErrNotImplemented || err == ErrTracerStillNotInitialized {
			return nil, nil
		}
		return nil, err
	}

	var aggregatedInterval time.Duration
	if !c.prevCheckTime.IsZero() {
		aggregatedInterval = currentTime.Sub(c.prevCheckTime)
	}

	httpStats := aggregateHTTPStats(conns.HTTP, aggregatedInterval, false)

	dnsMap := map[string][]dns.Hostname{}
	for ip, addrs := range conns.DNS {
		dnsMap[ip.String()] = addrs
	}
	log.Debugf("%v", dnsMap)

	containerToPod := c.podsCache.GetContainerToPodMap(context.TODO())

	formattedConnections, connsPods := c.formatConnections(cfg, conns.Conns, aggregatedInterval, httpStats, containerToPod)
	c.prevCheckTime = currentTime

	metrics := c.reportMetrics(cfg.HostName, conns, formattedConnections /*, conns.HTTPTelemetry*/)

	log.Infof("collected %d connections in %s", len(formattedConnections), time.Since(start))
	for _, conn := range formattedConnections {
		log.Debugf("%v", conn)
	}
	log.Debugf("collected %d http data", len(httpStats))
	for key, metrics := range httpStats {
		log.Debugf("http data for %s", key)
		for _, metric := range metrics {
			log.Debugf("\t%v", metric)
		}
	}

	log.Infof("collected %d pods for connections", len(connsPods.pods))
	for _, pod := range connsPods.pods {
		log.Debugf("%v", pod)
	}

	return &CheckResult{CollectorMessages: batchConnections(cfg, groupID, formattedConnections, connsPods, aggregatedInterval), Metrics: metrics}, nil
}

func (c *ConnectionsCheck) getConnections() (*network.Connections, error) {
	if c.useLocalTracer { // If local tracer is set up, use that
		if c.localTracer == nil {
			return nil, fmt.Errorf("using local network tracer, but no tracer was initialized")
		}
		cs, err := c.localTracer.GetActiveConnections("process-agent")
		return cs, err
	}

	return nil, fmt.Errorf("remote ConnectionTracker is not supported")
}

var logShortLivingNoticeOnce = &sync.Once{}

// this structure keeps list of pods that are related to observed connections
// relation to connection is defined by process id (pid)
type connectionsPodsIndex struct {
	pods        map[string]*model.Pod
	pidToPodUID map[int32]string
}

func (cp *connectionsPodsIndex) addPodWithPID(pod *kubelet.Pod, pid int32) {
	if _, ok := cp.pidToPodUID[pid]; ok {
		return // process has already added
	}
	cp.pidToPodUID[pid] = pod.Metadata.UID
	if modelPod, ok := cp.pods[pod.Metadata.UID]; ok {
		modelPod.Pids = append(modelPod.Pids, pid)
	} else {
		cp.pods[pod.Metadata.UID] = &model.Pod{
			Namespace: pod.Metadata.Namespace,
			Name:      pod.Metadata.Name,
			Uid:       pod.Metadata.UID,
			Labels:    pod.Metadata.Labels,
			Pids:      []int32{pid},
		}
	}
}

var (
	connectionCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "stackstate_process_agent",
		Subsystem: "connections",
		Name:      "processed",
		Help:      "Number of connections processed by the connections check",
	}, []string{"state"})
)

// Connections are split up into a chunks of at most 100 connections per message to
// limit the message size on intake.
func (c *ConnectionsCheck) formatConnections(
	cfg *config.AgentConfig,
	conns []network.ConnectionStats,
	prevCheckTimeDiff time.Duration,
	httpMetrics map[connKey][]*model.ConnectionMetric,
	containerToPod map[string]*kubelet.Pod,
) ([]*model.Connection, *connectionsPodsIndex) {
	// Process create-times required to construct unique process hash keys on the backend
	// attention! There is a conns.Conns[0].PidCreateTime, it is always zero, so we do have to look up the actual value
	processes := Process.getProcesses(connectionPIDs(conns))

	// build process to pod association
	connsPods := &connectionsPodsIndex{
		pods:        make(map[string]*model.Pod),
		pidToPodUID: make(map[int32]string),
	}
	for pid, process := range processes {
		if pod, ok := containerToPod[process.ContainerId]; ok {
			connsPods.addPodWithPID(pod, int32(pid))
			log.Tracef("found pod for container %s: %v", process.ContainerId, pod)
		} else {
			log.Debugf("not found pod for container %s", process.ContainerId)
		}
	}

	cxs := make([]*model.Connection, 0, len(conns))
	for _, conn := range conns {
		// Check to see if this is a process that we observed and that it's not short-lived / blacklisted in the Process check
		process, ok := processes[conn.Pid]
		if !ok {
			connectionCounter.WithLabelValues("no_process").Inc()
			log.Debugf("Filter connection: %v is out because process %d is not observed (gone or just started)", conn, conn.Pid)
			continue
		}
		pidCreateTime := process.CreateTime

		namespace := formatNamespace(cfg.ClusterName, cfg.HostName, conn)
		relationID, err := CreateNetworkRelationIdentifier(namespace, conn)
		if err != nil {
			connectionCounter.WithLabelValues("invalid").Inc()
			log.Warnf("invalid connection description - can't determine ID: %v", err)
			continue
		}
		// Check to see if we have this relation cached and whether we have observed it for the configured time, otherwise skip
		relationCache, ok := c.cache.IsNetworkRelationCached(relationID)
		// put it in the cache for the next run
		c.cache.PutNetworkRelationCache(relationID)

		if cfg.EnableShortLivedNetworkRelationFilter &&
			(!ok || isRelationShortLived(relationCache.FirstObserved, cfg)) {

			connectionCounter.WithLabelValues("short_living").Inc()
			logShortLivingNoticeOnce.Do(func() {
				log.Infof("Some of network relations are filtered out as short-living. " +
					"It means that we observed this / similar network relations less than %d seconds. If this behaviour is not desired set the " +
					"STS_NETWORK_RELATION_FILTER_SHORT_LIVED_QUALIFIER_SECS environment variable to 0, disable it in agent.yaml " +
					"under process_config.filters.short_lived_network_relations.enabled or increase the qualifier seconds using" +
					"process_config.filters.short_lived_network_relations.qualifier_secs.")
			})
			log.Debugf("Filter relation: %s (%v) based on it's short-lived nature; ",
				relationID, conn, cfg.ShortLivedNetworkRelationQualifierSecs,
			)
			continue
		}
		var natladdr, natraddr *model.Addr
		if conn.IPTranslation != nil && conn.IPTranslation.ReplSrcIP.IsZero() {
			natraddr = &model.Addr{
				Ip:   conn.IPTranslation.ReplSrcIP.String(),
				Port: int32(conn.IPTranslation.ReplSrcPort),
			}
		}
		if conn.IPTranslation != nil && conn.IPTranslation.ReplDstIP.IsZero() {
			natladdr = &model.Addr{
				Ip:   conn.IPTranslation.ReplDstIP.String(),
				Port: int32(conn.IPTranslation.ReplDstPort),
			}
		}

		// although fields are called Source and Dest, they are in fact local/remote
		localAddr := &model.Addr{
			Ip:   conn.Source.String(),
			Port: int32(conn.SPort),
		}
		remoteAddr := &model.Addr{
			Ip:   conn.Dest.String(),
			Port: int32(conn.DPort),
		}

		if conn.Direction != network.OUTGOING && conn.Direction != network.INCOMING {
			log.Warnf("unexpected connection direction %s for %v", conn.Direction.String(), conn)
		}

		appProto := ""
		metrics := httpMetrics[getConnectionKey(conn)]
		if len(metrics) > 0 {
			appProto = "http"
		}

		metrics = append(metrics, &model.ConnectionMetric{
			Name: string(bytesSentDelta),
			Tags: make(map[string]string),
			Value: &model.ConnectionMetricValue{
				Value: &model.ConnectionMetricValue_Number{
					Number: float64(conn.Last.SentBytes),
				},
			},
		})

		metrics = append(metrics, &model.ConnectionMetric{
			Name: string(bytesReceivedDelta),
			Tags: make(map[string]string),
			Value: &model.ConnectionMetricValue{
				Value: &model.ConnectionMetricValue_Number{
					Number: float64(conn.Last.RecvBytes),
				},
			},
		})

		cxs = append(cxs, &model.Connection{
			Pid:                    int32(conn.Pid),
			PidCreateTime:          pidCreateTime,
			Family:                 formatFamily(conn.Family),
			Type:                   formatType(conn.Type),
			Laddr:                  localAddr,
			Raddr:                  remoteAddr,
			Natladdr:               natladdr,
			Natraddr:               natraddr,
			BytesSentPerSecond:     float32(calculateNormalizedRate(conn.Last.SentBytes, prevCheckTimeDiff)),
			BytesReceivedPerSecond: float32(calculateNormalizedRate(conn.Last.RecvBytes, prevCheckTimeDiff)),
			Direction:              calculateDirection(conn.Direction),
			Namespace:              namespace,
			ConnectionIdentifier:   relationID,
			ApplicationProtocol:    appProto,
			Metrics:                metrics,
		})

		connectionCounter.WithLabelValues("reported").Inc()
		// put it in the cache for the next run
		c.cache.PutNetworkRelationCache(relationID)
	}

	return cxs, connsPods
}

type connKey struct {
	SrcIPHigh uint64
	SrcIPLow  uint64
	SrcPort   uint16
	DstIPHigh uint64
	DstIPLow  uint64
	DstPort   uint16
}

func getConnectionKey(conn network.ConnectionStats) connKey {
	var saddr, daddr util.Address
	var sport, dport uint16

	connIsIncoming := conn.Direction == network.INCOMING
	connLooksLikeIncoming := conn.Direction != network.OUTGOING && network.IsEphemeralPort(int(sport))

	if connIsIncoming || connLooksLikeIncoming {
		saddr, sport = network.GetNATRemoteAddress(conn)
		daddr, dport = network.GetNATLocalAddress(conn)
	} else {
		saddr, sport = network.GetNATLocalAddress(conn)
		daddr, dport = network.GetNATRemoteAddress(conn)
	}

	saddrl, saddrh := util.ToLowHigh(saddr)
	daddrl, daddrh := util.ToLowHigh(daddr)
	return connKey{
		SrcIPHigh: saddrh, SrcIPLow: saddrl, SrcPort: sport,
		DstIPHigh: daddrh, DstIPLow: daddrl, DstPort: dport,
	}
}

func getConnectionKeyForStats(key http.Key) connKey {
	return connKey{
		SrcIPHigh: key.SrcIPHigh,
		SrcIPLow:  key.SrcIPLow,
		SrcPort:   key.SrcPort,
		DstIPHigh: key.DstIPHigh,
		DstIPLow:  key.DstIPLow,
		DstPort:   key.DstPort,
	}
}

func statusCodeClassToString(class int) string {
	switch class {
	case 100:
		return "1xx"
	case 200:
		return "2xx"
	case 300:
		return "3xx"
	case 400:
		return "4xx"
	case 500:
		return "5xx"
	default:
		return ""
	}
}

type metricName string

const (
	/**
	 * Why are we useing delta's here? The best thing would be to use a cumulative counter. However, currently
	 * this data gets aggregated by the correllator. Aggregation of a counter in a streaming way is tough, because it requires
	 * detection of resets and lifecycle management of the inputs. Because of that, deltas are easier to aggregate.
	 *
	 * Only downside is that a counter is more robust. If a message gets lost along the way, a counter will fix that,
	 * a delta will not.
	 */
	bytesSentDelta     metricName = "bytes_sent_delta"
	bytesReceivedDelta metricName = "bytes_received_delta"

	httpResponseTime      metricName = "http_response_time_seconds"
	httpRequestsPerSecond metricName = "http_requests_per_second"
	httpRequestsDelta     metricName = "http_requests_delta"

	httpStatusCodeTag = "code"
	httpPathTag       = "path"
	httpMethodTag     = "method"
)

func emptySketch() *ddsketch.DDSketch {
	sketch, err := ddsketch.NewDefaultDDSketch(0.01)
	if err != nil {
		_ = log.Errorf("unexpected error from ddsketch constructor: %v", err)
		return nil
	}
	return sketch
}

type aggStatsKey struct {
	statusCode string
	path       string
	method     string
}

func (k aggStatsKey) toMap() map[string]string {
	tags := map[string]string{
		httpStatusCodeTag: k.statusCode,
	}
	if k.path != "" {
		tags[httpPathTag] = k.path
	}
	if k.method != "" {
		tags[httpMethodTag] = k.method
	}
	return tags
}

func aggregateStats(stats []http.RequestStat) (int, *ddsketch.DDSketch) {
	requestCount := 0
	latencies := emptySketch()
	for _, stat := range stats {
		requestCount += stat.Count
		if stat.Count == 0 {
			continue
		} else if stat.Count == 1 {
			latencies.Add(stat.FirstLatencySample * 0.000000001)
		} else {
			if stat.Latencies != nil {
				var scaled = emptySketch()
				scaled = stat.Latencies.ChangeMapping(scaled.IndexMapping, scaled.GetPositiveValueStore(), scaled.GetNegativeValueStore(), 0.000000001)
				latencies.MergeWith(scaled)
			}
		}
	}
	return requestCount, latencies
}

func aggregateHTTPStats(httpStats map[http.Key]*http.RequestStats, duration time.Duration, sendForPath bool) map[connKey][]*model.ConnectionMetric {
	result := map[connKey][]*model.ConnectionMetric{}

	// regrouping statistic
	// httpStats is map where key describes network connection along with Path & Method
	// RequestStats has statistics per response status group (1xx, 2xx etc.)
	// we need to group all path/method together to have overall statistics
	// and also to have generic groups regarding status code: any, success

	regroupedStats := map[connKey]map[aggStatsKey][]http.RequestStat{}

	appendStats := func(acc map[aggStatsKey][]http.RequestStat, stats *http.RequestStat, tags aggStatsKey) map[aggStatsKey][]http.RequestStat {
		if acc == nil {
			acc = map[aggStatsKey][]http.RequestStat{}
		}
		accStat, _ := acc[tags]
		acc[tags] = append(accStat, *stats)
		return acc
	}

	appendStatsForStatusGroup := func(connStats map[aggStatsKey][]http.RequestStat, statusCodeGroup string, httpKey http.Key, stat *http.RequestStat) map[aggStatsKey][]http.RequestStat {
		connStats = appendStats(connStats, stat, aggStatsKey{
			statusCode: statusCodeGroup,
		})
		if sendForPath {
			connStats = appendStats(connStats, stat, aggStatsKey{
				statusCode: statusCodeGroup,
				method:     httpKey.Method.String(),
				path:       httpKey.Path.Content,
			})
		}
		return connStats
	}

	for statKey, statsByCode := range httpStats {
		for statusCodeClass := 100; statusCodeClass <= 500; statusCodeClass += 100 {
			stat := statsByCode.Stats(statusCodeClass)
			// Okay here it goes. When there is not data, we still want to produce a '0' line, so we produce the empty data.
			if stat == nil {
				stat = &http.RequestStat{}
			}

			statusCodeGroup := statusCodeClassToString(statusCodeClass)
			if statusCodeGroup == "" {
				continue
			}
			connKey := getConnectionKeyForStats(statKey)
			connStats := regroupedStats[connKey]

			connStats = appendStatsForStatusGroup(connStats, statusCodeGroup, statKey, stat)

			regroupedStats[connKey] = connStats
		}
	}

	// format regrouped statistics

	for connKey, statsByTags := range regroupedStats {
		for tagsKey, stats := range statsByTags {
			requestCount, latencies := aggregateStats(stats)
			result[connKey] = append(result[connKey],
				makeConnectionMetricWithNumber(
					httpRequestsDelta, tagsKey.toMap(),
					float64(requestCount),
				),
				makeConnectionMetricWithNumber(
					httpRequestsPerSecond, tagsKey.toMap(),
					calculateNormalizedRate(uint64(requestCount), duration),
				),
				makeConnectionMetricWithHistogram(
					httpResponseTime, tagsKey.toMap(),
					latencies,
				),
			)
		}
	}

	return result
}

func makeConnectionMetricWithHistogram(name metricName, tags map[string]string, histogram *ddsketch.DDSketch) *model.ConnectionMetric {
	return &model.ConnectionMetric{
		Name: string(name),
		Tags: tags,
		Value: &model.ConnectionMetricValue{
			Value: &model.ConnectionMetricValue_Histogram{
				Histogram: histogram.ToProto(),
			},
		},
	}
}

func makeConnectionMetricWithNumber(name metricName, tags map[string]string, number float64) *model.ConnectionMetric {
	return &model.ConnectionMetric{
		Name: string(name),
		Tags: tags,
		Value: &model.ConnectionMetricValue{
			Value: &model.ConnectionMetricValue_Number{
				Number: number,
			},
		},
	}
}

func batchConnections(cfg *config.AgentConfig, groupID int32, cxs []*model.Connection, connsPods *connectionsPodsIndex, interval time.Duration) []model.MessageBody {
	groupSize := groupSize(len(cxs), cfg.MaxConnectionsPerMessage)
	batches := make([]model.MessageBody, 0, groupSize)

	// picks only pods that are related to specified list of connections
	podsForConnections := func(cxs []*model.Connection) []*model.Pod {
		podsMap := map[string]*model.Pod{}
		for _, conn := range cxs {
			if uid, ok := connsPods.pidToPodUID[conn.Pid]; ok {
				if pod, ok := connsPods.pods[uid]; ok {
					podsMap[uid] = pod
				}
			}
		}
		podsList := make([]*model.Pod, 0, len(podsMap))
		for _, pod := range podsMap {
			podsList = append(podsList, pod)
		}
		return podsList
	}

	for len(cxs) > 0 {
		batchSize := min(cfg.MaxConnectionsPerMessage, len(cxs))

		batch := &model.CollectorConnections{
			HostName:           cfg.HostName,
			Connections:        cxs[:batchSize],
			GroupId:            groupID,
			GroupSize:          groupSize,
			CollectionInterval: int32(interval / time.Millisecond),
			Pods:               podsForConnections(cxs[:batchSize]),
		}
		if strings.TrimSpace(cfg.ClusterName) != "" {
			batch.ClusterName = cfg.ClusterName
		}

		batches = append(batches, batch)
		cxs = cxs[batchSize:]
	}

	return batches
}

func groupSize(total, maxBatchSize int) int32 {
	groupSize := total / maxBatchSize
	if total%maxBatchSize > 0 {
		groupSize++
	}
	return int32(groupSize)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func connectionPIDs(conns []network.ConnectionStats) []uint32 {
	ps := make(map[uint32]struct{}) // Map used to represent a set
	for _, c := range conns {
		ps[c.Pid] = struct{}{}
	}

	pids := make([]uint32, 0, len(ps))
	for pid := range ps {
		pids = append(pids, pid)
	}
	return pids
}

// isRelationShortLived checks to see whether a network connection is considered a short-lived network relation
func isRelationShortLived(firstObserved int64, cfg *config.AgentConfig) bool {

	// firstObserved is before ShortLivedTime. Relation is not short-lived, return false
	if time.Unix(firstObserved, 0).Before(time.Now().Add(-cfg.ShortLivedNetworkRelationQualifierSecs)) {
		return false
	}
	return true
}

type reportedProps struct {
	nat        bool
	connFamily model.ConnectionFamily
	connType   model.ConnectionType
	direction  model.ConnectionDirection
	appProto   string
}

func (rp *reportedProps) Tags() []string {
	result := []string{
		"ipver:" + rp.connFamily.String(),
		"proto:" + rp.connType.String(),
		"direction:" + rp.direction.String(),
	}
	if rp.nat {
		result = append(result, "nat:true")
	} else {
		result = append(result, "nat:false")
	}
	if rp.appProto != "" {
		result = append(result, "app_proto:"+rp.appProto)
	}
	return result
}

func (c *ConnectionsCheck) reportMetrics(hostname string, allConnections *network.Connections, reportedConnections []*model.Connection) []telemetry.RawMetric {
	metrics := make([]telemetry.RawMetric, 0)

	metrics = append(metrics, telemetry.MakeRawMetric("stackstate.process_agent.connections.total", hostname, float64(len(allConnections.Conns)), []string{}))

	reportedBreakdown := map[reportedProps]int{}
	for _, conn := range reportedConnections {
		props := reportedProps{
			nat:        conn.Natladdr != nil || conn.Natraddr != nil,
			connFamily: conn.Family,
			connType:   conn.Type,
			direction:  conn.Direction,
			appProto:   conn.ApplicationProtocol,
		}
		count, _ := reportedBreakdown[props]
		reportedBreakdown[props] = count + 1
	}

	for props, count := range reportedBreakdown {
		metrics = append(metrics, telemetry.MakeRawMetric("stackstate.process_agent.connections.reported", hostname, float64(count), props.Tags()))
	}

	return metrics
}
