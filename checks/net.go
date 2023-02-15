package checks

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/StackVista/stackstate-agent/pkg/aggregator"
	"github.com/StackVista/stackstate-agent/pkg/ebpf"
	"github.com/StackVista/stackstate-agent/pkg/network"
	"github.com/StackVista/stackstate-agent/pkg/network/http"
	"github.com/StackVista/stackstate-agent/pkg/network/tracer"
	"github.com/StackVista/stackstate-agent/pkg/process/util"
	"github.com/StackVista/stackstate-process-agent/pkg/pods"
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

	podsWatcher *pods.Watcher

	prevCheckTime time.Time

	buf *bytes.Buffer // Internal buffer

	// Use this as the network relation cache to calculate rate metrics and drop short-lived network relations
	cache *NetworkRelationCache
}

// Name returns the name of the ConnectionsCheck.
func (c *ConnectionsCheck) Name() string { return "connections" }

// Endpoint returns the endpoint where this check is submitted.
func (c *ConnectionsCheck) Endpoint() string { return "/api/v1/connections" }

// RealTime indicates if this check only runs in real-time mode.
func (c *ConnectionsCheck) RealTime() bool { return false }

// Sender returns an instance of the check sender
func (c *ConnectionsCheck) Sender() aggregator.Sender {
	return GetSender(c.Name())
}

// Run runs the ConnectionsCheck to collect the live TCP connections on the
// system. Currently only linux systems are supported as eBPF is used to gather
// this information. For each connection we'll return a `model.Connection`
// that will be bundled up into a `CollectorConnections`.
// See agent.proto for the schema of the message and models.
func (c *ConnectionsCheck) Run(cfg *config.AgentConfig, features features.Features, groupID int32, currentTime time.Time) (*CheckResult, error) {
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

	dnsMap := map[string][]string{}
	for ip, addrs := range conns.DNS {
		dnsMap[ip.String()] = addrs
	}
	log.Debugf("%v", dnsMap)

	formattedConnections, stats, connsPods := c.formatConnections(cfg, conns.Conns, aggregatedInterval, httpStats)
	c.prevCheckTime = currentTime

	c.reportMetrics(cfg.HostName, conns, formattedConnections, stats, conns.HTTPTelemetry)

	log.Debugf("collected %d connections in %s", len(formattedConnections), time.Since(start))
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

	return &CheckResult{CollectorMessages: batchConnections(cfg, groupID, formattedConnections, connsPods, aggregatedInterval)}, nil
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

type formattingStats struct {
	NoProcess   int
	Invalid     int
	ShortLiving int
}

var logShortLivingNoticeOnce = &sync.Once{}

type connectionsPodsIndex struct {
	pods        map[string]*model.Pod
	pidToPodUid map[uint32]string
}

// Connections are split up into a chunks of at most 100 connections per message to
// limit the message size on intake.
func (c *ConnectionsCheck) formatConnections(
	cfg *config.AgentConfig,
	conns []network.ConnectionStats,
	prevCheckTimeDiff time.Duration,
	httpMetrics map[connKey][]*model.ConnectionMetric) ([]*model.Connection, *formattingStats, *connectionsPodsIndex) {
	stats := &formattingStats{}
	// Process create-times required to construct unique process hash keys on the backend
	// attention! There is a conns.Conns[0].PidCreateTime, it is always zero, so we do have to look up the actual value
	processes := Process.getProcesses(connectionPIDs(conns))

	connsPods := &connectionsPodsIndex{
		pods:        make(map[string]*model.Pod),
		pidToPodUid: make(map[uint32]string),
	}

	cxs := make([]*model.Connection, 0, len(conns))
	for _, conn := range conns {
		// Check to see if this is a process that we observed and that it's not short-lived / blacklisted in the Process check
		process, ok := processes[conn.Pid]
		if !ok {
			stats.NoProcess++
			log.Debugf("Filter connection: %v is out because process %d is not observed (gone or just started)", conn, conn.Pid)
			continue
		}
		pidCreateTime := process.CreateTime
		if c.podsWatcher != nil {
			pod := c.podsWatcher.GetPodForContainerID(process.ContainerId)
			if pod != nil {
				if outPod, ok := connsPods.pods[pod.Metadata.UID]; !ok {
					connsPods.pods[pod.Metadata.UID] = &model.Pod{
						Namespace: pod.Metadata.Namespace,
						Name:      pod.Metadata.Name,
						Uid:       pod.Metadata.UID,
						Labels:    pod.Metadata.Labels,
						Pids:      []uint32{conn.Pid},
					}
					connsPods.pidToPodUid[conn.Pid] = pod.Metadata.UID
				} else {
					outPod.Pids = append(outPod.Pids, conn.Pid)
					connsPods.pidToPodUid[conn.Pid] = pod.Metadata.UID // TODO consider process create time
				}
				log.Debugf("found pod for container %s: %v", process.ContainerId, pod)
			} else {
				log.Debugf("not found pod for container %s", process.ContainerId)
			}
		} else {
			log.Debugf("podsWatcher is not initialized")
		}

		namespace := formatNamespace(cfg.ClusterName, cfg.HostName, conn)
		relationID, err := CreateNetworkRelationIdentifier(namespace, conn)
		if err != nil {
			stats.Invalid++
			log.Warnf("invalid connection description - can't determine ID: %v", err)
			continue
		}
		// Check to see if we have this relation cached and whether we have observed it for the configured time, otherwise skip
		relationCache, ok := c.cache.IsNetworkRelationCached(relationID)
		// put it in the cache for the next run
		c.cache.PutNetworkRelationCache(relationID)

		if cfg.EnableShortLivedNetworkRelationFilter &&
			(!ok || isRelationShortLived(relationCache.FirstObserved, cfg)) {

			stats.ShortLiving++
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
		if conn.IPTranslation != nil && conn.IPTranslation.ReplSrcIP != nil {
			natraddr = &model.Addr{
				Ip:   conn.IPTranslation.ReplSrcIP.String(),
				Port: int32(conn.IPTranslation.ReplSrcPort),
			}
		}
		if conn.IPTranslation != nil && conn.IPTranslation.ReplDstIP != nil {
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

		cxs = append(cxs, &model.Connection{
			Pid:                    int32(conn.Pid),
			PidCreateTime:          pidCreateTime,
			Family:                 formatFamily(conn.Family),
			Type:                   formatType(conn.Type),
			Laddr:                  localAddr,
			Raddr:                  remoteAddr,
			Natladdr:               natladdr,
			Natraddr:               natraddr,
			BytesSentPerSecond:     float32(calculateNormalizedRate(conn.LastSentBytes, prevCheckTimeDiff)),
			BytesReceivedPerSecond: float32(calculateNormalizedRate(conn.LastRecvBytes, prevCheckTimeDiff)),
			Direction:              calculateDirection(conn.Direction),
			Namespace:              namespace,
			ConnectionIdentifier:   relationID,
			ApplicationProtocol:    appProto,
			Metrics:                metrics,
		})

		// put it in the cache for the next run
		c.cache.PutNetworkRelationCache(relationID)
	}

	return cxs, stats, connsPods
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
	case 0:
		return "1xx"
	case 1:
		return "2xx"
	case 2:
		return "3xx"
	case 3:
		return "4xx"
	case 4:
		return "5xx"
	default:
		return ""
	}
}

type metricName string

const (
	httpResponseTime      metricName = "http_response_time_seconds"
	httpRequestsPerSecond metricName = "http_requests_per_second"

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

type requestStats struct {
	Count              int
	Latencies          *ddsketch.DDSketch
	FirstLatencySample float64
}

func aggregateStats(stats []requestStats) (int, *ddsketch.DDSketch) {
	requestCount := 0
	latencies := emptySketch()
	for _, stat := range stats {
		requestCount += stat.Count
		if stat.Latencies != nil {
			latencies.MergeWith(stat.Latencies)
		} else if stat.Count > 0 {
			latencies.Add(stat.FirstLatencySample)
		}
	}
	return requestCount, latencies
}

func aggregateHTTPStats(httpStats map[http.Key]http.RequestStats, duration time.Duration, sendForPath bool) map[connKey][]*model.ConnectionMetric {
	result := map[connKey][]*model.ConnectionMetric{}

	// regrouping statistic
	// httpStats is map where key describes network connection along with Path & Method
	// RequestStats has statistics per response status group (1xx, 2xx etc.)
	// we need to group all path/method together to have overall statistics
	// and also to have generic groups regarding status code: any, success

	regroupedStats := map[connKey]map[aggStatsKey][]requestStats{}

	appendStats := func(acc map[aggStatsKey][]requestStats, stats requestStats, tags aggStatsKey) map[aggStatsKey][]requestStats {
		if acc == nil {
			acc = map[aggStatsKey][]requestStats{}
		}
		accStat, _ := acc[tags]
		acc[tags] = append(accStat, stats)
		return acc
	}

	appendStatsForStatusGroup := func(connStats map[aggStatsKey][]requestStats, statusCodeGroup string, httpKey http.Key, stats requestStats) map[aggStatsKey][]requestStats {
		connStats = appendStats(connStats, stats, aggStatsKey{
			statusCode: statusCodeGroup,
		})
		if sendForPath {
			connStats = appendStats(connStats, stats, aggStatsKey{
				statusCode: statusCodeGroup,
				method:     httpKey.Method.String(),
				path:       httpKey.Path,
			})
		}
		return connStats
	}

	for statKey, statsByCode := range httpStats {
		for statusCodeClass, stats := range statsByCode {
			statusCodeGroup := statusCodeClassToString(statusCodeClass)
			if statusCodeGroup == "" {
				continue
			}
			connKey := getConnectionKeyForStats(statKey)
			connStats := regroupedStats[connKey]

			connStats = appendStatsForStatusGroup(connStats, statusCodeGroup, statKey, stats)
			connStats = appendStatsForStatusGroup(connStats, "any", statKey, stats)
			if statusCodeGroup == "1xx" || statusCodeGroup == "2xx" || statusCodeGroup == "3xx" {
				connStats = appendStatsForStatusGroup(connStats, "success", statKey, stats)
			}

			regroupedStats[connKey] = connStats
		}
	}

	// format regrouped statistics

	for connKey, statsByTags := range regroupedStats {
		for tagsKey, stats := range statsByTags {
			requestCount, latencies := aggregateStats(stats)
			result[connKey] = append(result[connKey],
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

	podsForConnections := func(cxs []*model.Connection) []*model.Pod {
		podsMap := map[string]*model.Pod{}
		for _, conn := range cxs {
			if uid, ok := connsPods.pidToPodUid[uint32(conn.Pid)]; ok {
				if pod, ok := connsPods.pods[uid]; ok {
					podsMap[uid] = pod
				}
			}
		}
		pods := make([]*model.Pod, 0, len(podsMap))
		for _, pod := range podsMap {
			pods = append(pods, pod)
		}
		return pods
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

func (c *ConnectionsCheck) reportMetrics(hostname string, allConnections *network.Connections, reportedConnections []*model.Connection, filterStats *formattingStats, telemetry *http.TelemetryStats) {
	c.Sender().Gauge("stackstate.process_agent.connections.total", float64(len(allConnections.Conns)), hostname, []string{})

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
		c.Sender().Gauge("stackstate.process_agent.connections.reported",
			float64(count), hostname, props.Tags(),
		)
	}

	if telemetry != nil {
		//Misses   int64 // this happens when we can't cope with the rate of events
		//Dropped  int64 // this happens when httpStatKeeper reaches capacity
		//Rejected int64 // this happens when a user-defined reject-filter matches a request
		c.Sender().Gauge("stackstate.process_agent.connections.http.misses", float64(telemetry.Misses), hostname, []string{})
		c.Sender().Gauge("stackstate.process_agent.connections.http.dropped", float64(telemetry.Dropped), hostname, []string{})
		c.Sender().Gauge("stackstate.process_agent.connections.http.rejected", float64(telemetry.Rejected), hostname, []string{})
	}

	c.Sender().Gauge("stackstate.process_agent.connections.no_process", float64(filterStats.NoProcess), hostname, []string{})
	c.Sender().Gauge("stackstate.process_agent.connections.invalid", float64(filterStats.Invalid), hostname, []string{})
	c.Sender().Gauge("stackstate.process_agent.connections.short_living", float64(filterStats.ShortLiving), hostname, []string{})
}
