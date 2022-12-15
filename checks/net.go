package checks

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/DataDog/agent-payload/v5/process"
	"github.com/StackVista/stackstate-agent/pkg/aggregator"
	"github.com/StackVista/stackstate-agent/pkg/ebpf"
	"github.com/StackVista/stackstate-agent/pkg/network"
	"github.com/StackVista/stackstate-agent/pkg/network/http"
	"github.com/StackVista/stackstate-agent/pkg/network/tracer"
	"github.com/StackVista/stackstate-agent/pkg/process/util"
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

	prevCheckTime time.Time

	buf *bytes.Buffer // Internal buffer

	// Use this as the network relation cache to calculate rate metrics and drop short-lived network relations
	cache *NetworkRelationCache
}

type connectionMetrics struct {
	SendBytes uint64
	RecvBytes uint64
}

type statusCodeGroup struct {
	// Local network tracer
	tag      string
	inRange  func(int) bool
	ddSketch *ddsketch.DDSketch
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
	fmt.Printf("%v", dnsMap)

	formattedConnections, stats := c.formatConnections(cfg, conns.Conns, aggregatedInterval, httpStats)
	c.prevCheckTime = currentTime

	c.reportMetrics(cfg.HostName, conns, formattedConnections, stats)

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
	return &CheckResult{CollectorMessages: batchConnections(cfg, groupID, formattedConnections, aggregatedInterval)}, nil
}

func (c *ConnectionsCheck) getConnections() (*network.Connections, error) {
	if c.useLocalTracer { // If local tracer is set up, use that
		if c.localTracer == nil {
			return nil, fmt.Errorf("using local network tracer, but no tracer was initialized")
		}
		cs, err := c.localTracer.GetActiveConnections("process-agent")
		return cs, err
	}

	// TODO ????
	//tu, err := net.GetRemoteNetworkTracerUtil()
	//if err != nil {
	//	if net.ShouldLogTracerUtilError() {
	//		return nil, err
	//	}
	//	return nil, ErrTracerStillNotInitialized
	//}

	return nil, fmt.Errorf("remote ConnectionTracker is not supported")
}

type FormatStats struct {
	NoProcess   int
	Invalid     int
	ShortLiving int
}

var logShortLivingNoticeOnce = &sync.Once{}

// Connections are split up into a chunks of at most 100 connections per message to
// limit the message size on intake.
func (c *ConnectionsCheck) formatConnections(
	cfg *config.AgentConfig,
	conns []network.ConnectionStats,
	prevCheckTimeDiff time.Duration,
	httpMetrics map[connKey][]*model.ConnectionMetric) ([]*model.Connection, *FormatStats) {
	stats := &FormatStats{}
	// Process create-times required to construct unique process hash keys on the backend
	// attention! There is a conns.Conns[0].PidCreateTime, it is always zero, so we do have to look up the actual value
	createTimeForPID := Process.createTimesForPIDs(connectionPIDs(conns))

	cxs := make([]*model.Connection, 0, len(conns))
	for _, conn := range conns {
		// Check to see if this is a process that we observed and that it's not short-lived / blacklisted in the Process check

		pidCreateTime, ok := isProcessPresent(createTimeForPID, conn.Pid)
		if !ok {
			stats.NoProcess += 1
			log.Debugf("connection %v is filtered out because process %d is not observed (finished or just started)", conn, conn.Pid)
			continue
		}

		namespace := formatNamespace(cfg.ClusterName, cfg.HostName, conn)
		relationID, err := CreateNetworkRelationIdentifier(namespace, conn)
		if err != nil {
			stats.Invalid += 1
			log.Warnf("invalid connection description - can't determine ID: %v", err)
			continue
		}
		// Check to see if we have this relation cached and whether we have observed it for the configured time, otherwise skip
		relationCache, ok := c.cache.IsNetworkRelationCached(relationID)
		// put it in the cache for the next run
		c.cache.PutNetworkRelationCache(relationID)

		if cfg.EnableShortLivedNetworkRelationFilter &&
			(!ok || isRelationShortLived(relationID, relationCache.FirstObserved, cfg)) {

			stats.ShortLiving += 1
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

		sourceAddr := &model.Addr{
			Ip:   conn.Source.String(),
			Port: int32(conn.SPort),
		}
		destAddr := &model.Addr{
			Ip:   conn.Dest.String(),
			Port: int32(conn.DPort),
		}

		var localAddr, remoteAddr *model.Addr
		if conn.Direction == network.INCOMING {
			localAddr, remoteAddr = destAddr, sourceAddr
		} else {
			localAddr, remoteAddr = sourceAddr, destAddr
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

	return cxs, stats
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

	if conn.Direction == network.INCOMING || network.IsEphemeralPort(int(sport)) {
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

type MetricName string

const (
	http_ResponseTime      MetricName = "http_response_time_seconds"
	http_RequestsPerSecond MetricName = "http_requests_per_second"

	http_StatusCodeTag = "code"
	http_PathTag       = "path"
	http_MethodTag     = "method"
)

func emptySketch() *ddsketch.DDSketch {
	sketch, err := ddsketch.LogCollapsingLowestDenseDDSketch(0.01, 1024)
	if err != nil {
		_ = log.Errorf("unexpected error from ddsketch constructor: %v", err)
		return nil
	}
	return sketch
}

func getSketchAnyway(stats struct {
	Count              int
	Latencies          *ddsketch.DDSketch
	FirstLatencySample float64
}) *ddsketch.DDSketch {
	sketch := stats.Latencies
	if sketch == nil {
		sketch = emptySketch()
		if sketch != nil && stats.Count > 0 {
			_ = sketch.Add(stats.FirstLatencySample)
		}
	}
	return sketch
}

func erasePath(httpStats map[http.Key]http.RequestStats) map[http.Key]http.RequestStats {
	result := map[http.Key]http.RequestStats{}
	for statKey, stats := range httpStats {
		keyNoPath := statKey
		keyNoPath.Path = ""
		accStats, _ := result[keyNoPath]
		accStats.CombineWith(stats)
		result[keyNoPath] = accStats
	}
	return result
}

func aggregateHTTPStats(httpStats map[http.Key]http.RequestStats, duration time.Duration, sendForPath bool) map[connKey][]*model.ConnectionMetric {
	result := map[connKey][]*model.ConnectionMetric{}

	resultAppend := func(key connKey, metric *model.ConnectionMetric) {
		metrics, _ := result[key]
		result[key] = append(metrics, metric)
	}

	httpStatsWithoutPath := erasePath(httpStats)

	for statKey, statsByCode := range httpStatsWithoutPath {
		for statusCodeClass, stats := range statsByCode {
			statusCodeGroup := statusCodeClassToString(statusCodeClass)
			if statusCodeGroup == "" {
				continue
			}
			connKey := getConnectionKeyForStats(statKey)
			tags := map[string]string{
				http_StatusCodeTag: statusCodeGroup,
				//http_MethodTag:     statKey.Method.String(),
				//http_PathTag:       statKey.Path,
			}

			resultAppend(connKey, makeConnectionMetricWithNumber(
				http_RequestsPerSecond, tags,
				calculateNormalizedRate(uint64(stats.Count), duration),
			))
			resultAppend(connKey, makeConnectionMetricWithHistogram(
				http_ResponseTime, tags,
				getSketchAnyway(stats),
			))
		}
	}
	return nil
}

func makeConnectionMetricWithHistogram(name MetricName, tags map[string]string, histogram *ddsketch.DDSketch) *model.ConnectionMetric {
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

func makeConnectionMetricWithNumber(name MetricName, tags map[string]string, number float64) *model.ConnectionMetric {
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

func batchConnections(cfg *config.AgentConfig, groupID int32, cxs []*model.Connection, interval time.Duration) []model.MessageBody {
	groupSize := groupSize(len(cxs), cfg.MaxConnectionsPerMessage)
	batches := make([]model.MessageBody, 0, groupSize)

	for len(cxs) > 0 {
		batchSize := min(cfg.MaxConnectionsPerMessage, len(cxs))

		batch := &model.CollectorConnections{
			HostName:           cfg.HostName,
			Connections:        cxs[:batchSize],
			GroupId:            groupID,
			GroupSize:          groupSize,
			CollectionInterval: int32(interval / time.Millisecond),
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

// isProcessPresent checks to see if this process was present in the pidCreateTimes map created by the Process check,
// otherwise we don't report connections for this pid
func isProcessPresent(pidCreateTimes map[uint32]int64, pid uint32) (int64, bool) {
	pidCreateTime, ok := pidCreateTimes[pid]
	if !ok {
		log.Debugf("Filter connection: it's corresponding pid [%d] is not present in the last process state", pid)
		return pidCreateTime, false
	}

	return pidCreateTime, true
}

// isRelationShortLived checks to see whether a network connection is considered a short-lived network relation
func isRelationShortLived(relationID string, firstObserved int64, cfg *config.AgentConfig) bool {

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

func (c *ConnectionsCheck) reportMetrics(hostname string, allConnections *network.Connections, reportedConnections []*model.Connection, filterStats *FormatStats) {
	c.Sender().Gauge("stackstate.process_agent.connnections.total", float64(len(allConnections.Conns)), hostname, []string{})

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
		c.Sender().Gauge("stackstate.process_agent.connnections.reported",
			float64(count), hostname, props.Tags(),
		)
	}

	c.Sender().Gauge("stackstate.process_agent.connnections.no_process", float64(filterStats.NoProcess), hostname, []string{})
	c.Sender().Gauge("stackstate.process_agent.connnections.invalid", float64(filterStats.Invalid), hostname, []string{})
	c.Sender().Gauge("stackstate.process_agent.connnections.short_living", float64(filterStats.ShortLiving), hostname, []string{})
}

// TODO reuse from main agent
// Build the key for the http map based on whether the local or remote side is http.
func httpKeyFromConn(c *process.Connection) http.Key {
	// Retrieve translated addresses
	laddr, lport := GetNATLocalAddress(c)
	raddr, rport := GetNATRemoteAddress(c)

	// HTTP data is always indexed as (client, server), so we flip
	// the lookup key if necessary using the port range heuristic
	if network.IsEphemeralPort(int(lport)) {
		return http.NewKey(laddr, raddr, lport, rport, "", http.MethodUnknown)
	}

	return http.NewKey(raddr, laddr, rport, lport, "", http.MethodUnknown)
}

// GetNATLocalAddress returns the translated (local ip, local port) pair
func GetNATLocalAddress(c *process.Connection) (util.Address, uint16) {
	localIP := util.AddressFromString(c.Laddr.Ip)
	localPort := c.Laddr.Port

	if c.IpTranslation != nil && c.IpTranslation.ReplDstIP != "" {
		// Fields are flipped
		localIP = util.AddressFromString(c.IpTranslation.ReplDstIP)
		localPort = c.IpTranslation.ReplDstPort
	}
	return localIP, uint16(localPort)
}

// GetNATRemoteAddress returns the translated (remote ip, remote port) pair
func GetNATRemoteAddress(c *process.Connection) (util.Address, uint16) {
	remoteIP := util.AddressFromString(c.Raddr.Ip)
	remotePort := c.Raddr.Port

	if c.IpTranslation != nil && c.IpTranslation.ReplDstIP != "" {
		// Fields are flipped
		remoteIP = util.AddressFromString(c.IpTranslation.ReplSrcIP)
		remotePort = c.IpTranslation.ReplSrcPort
	}
	return remoteIP, uint16(remotePort)
}
