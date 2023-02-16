package checks

import (
	"bytes"
	"fmt"
	"github.com/DataDog/sketches-go/ddsketch"
	"github.com/StackVista/stackstate-agent/pkg/network"
	"github.com/StackVista/stackstate-agent/pkg/network/http"
	"github.com/StackVista/stackstate-agent/pkg/process/util"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/patrickmn/go-cache"

	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/stretchr/testify/assert"
)

func makeConnection(pid int32) *model.Connection {
	return &model.Connection{Pid: pid}
}

func TestNetworkConnectionBatching(t *testing.T) {
	p := []*model.Connection{
		makeConnection(1),
		makeConnection(2),
		makeConnection(3),
		makeConnection(4),
	}

	cfg := config.NewDefaultAgentConfig()

	for i, tc := range []struct {
		cur, last      []*model.Connection
		maxSize        int
		expectedTotal  int
		expectedChunks int
	}{
		{
			cur:            []*model.Connection{p[0], p[1], p[2]},
			maxSize:        1,
			expectedTotal:  3,
			expectedChunks: 3,
		},
		{
			cur:            []*model.Connection{p[0], p[1], p[2]},
			maxSize:        2,
			expectedTotal:  3,
			expectedChunks: 2,
		},
		{
			cur:            []*model.Connection{p[0], p[1], p[2], p[3]},
			maxSize:        10,
			expectedTotal:  4,
			expectedChunks: 1,
		},
		{
			cur:            []*model.Connection{p[0], p[1], p[2], p[3]},
			maxSize:        3,
			expectedTotal:  4,
			expectedChunks: 2,
		},
		{
			cur:            []*model.Connection{p[0], p[1], p[2], p[3], p[2], p[3]},
			maxSize:        2,
			expectedTotal:  6,
			expectedChunks: 3,
		},
	} {
		cfg.MaxConnectionsPerMessage = tc.maxSize
		chunks := batchConnections(cfg, 0, tc.cur, 10000000)

		assert.Len(t, chunks, tc.expectedChunks, "len %d", i)
		total := 0
		for _, c := range chunks {
			connections := c.(*model.CollectorConnections)
			total += len(connections.Connections)
			assert.Equal(t, int32(tc.expectedChunks), connections.GroupSize, "group size test %d", i)
			assert.Equal(t, int32(10), connections.GetCollectionInterval())
		}
		assert.Equal(t, tc.expectedTotal, total, "total test %d", i)
	}
}

func makeProcessConnection(pid uint32, local, remote string, localPort, remotePort uint16) network.ConnectionStats {
	return network.ConnectionStats{
		Pid:       pid,
		Type:      network.TCP,
		Family:    network.AFINET,
		Direction: network.OUTGOING,
		Source:    util.AddressFromString(local),
		SPort:     localPort,
		Dest:      util.AddressFromString(remote),
		DPort:     remotePort,
		NetNS:     1,
	}
}

func amendConnectionStats(stats network.ConnectionStats, sent, received uint64) network.ConnectionStats {
	stats.LastSentBytes = sent - stats.LastSentBytes
	stats.LastRecvBytes = received - stats.LastRecvBytes
	return stats
}

func makeConnectionStatsNoNs(pid uint32, local, remote string, localPort, remotePort uint16) network.ConnectionStats {
	return network.ConnectionStats{
		Pid:       pid,
		Type:      network.TCP,
		Family:    network.AFINET,
		Direction: network.OUTGOING,
		Source:    util.AddressFromString(local),
		SPort:     localPort,
		Dest:      util.AddressFromString(remote),
		DPort:     remotePort,
	}
}

func TestNetworkRelationCacheExpiration(t *testing.T) {
	cache := NewNetworkRelationCache(100 * time.Millisecond)
	hostname := "example.org"
	addStats := func(conns ...network.ConnectionStats) {
		for _, conn := range conns {
			relationID, _ := CreateNetworkRelationIdentifier(hostname, conn)
			cache.PutNetworkRelationCache(relationID)
		}
	}

	addStats(
		makeProcessConnection(1, "10.0.0.1", "10.0.0.2", 12345, 8080),
	)
	assert.Equal(t, 1, cache.ItemCount())

	time.Sleep(50 * time.Millisecond)

	addStats(
		// a new connection for existing relation (remote port 8080)
		makeProcessConnection(1, "10.0.0.1", "10.0.0.2", 12346, 8080),
		// a new connection for a new relation (remote port 2000)
		makeProcessConnection(1, "10.0.0.1", "10.0.0.2", 1000, 2000),
	)
	assert.Equal(t, 2, cache.ItemCount()) // should be now 2 relations in total

	time.Sleep(70 * time.Millisecond)
	// now the very first connection should be expired as 70+50 > 100 ms has elapsed
	assert.Equal(t, 2, cache.ItemCount())

	addStats(
		// a new connection for existing relation (remote port 8080)
		makeProcessConnection(1, "10.0.0.1", "10.0.0.2", 12347, 8080),
	)
	assert.Equal(t, 2, cache.ItemCount())

	time.Sleep(110 * time.Millisecond)
	// now everything should go away
	assert.Equal(t, 0, cache.ItemCount())
}

func TestFilterConnectionsByProcess(t *testing.T) {
	cfg := config.NewDefaultAgentConfig()
	now := time.Now()
	c := &ConnectionsCheck{
		buf:   new(bytes.Buffer),
		cache: NewNetworkRelationCache(cfg.NetworkRelationCacheDurationMin),
	}

	// create the connection stats
	connStats := []network.ConnectionStats{
		makeProcessConnection(1, "10.0.0.1", "10.0.0.2", 12345, 8080),
		makeProcessConnection(2, "10.0.0.1", "10.0.0.3", 12346, 8080),
		makeProcessConnection(3, "10.0.0.1", "10.0.0.4", 12347, 8080),
		makeProcessConnection(4, "10.0.0.1", "10.0.0.5", 12348, 8080),
	}

	// fill in the relation cache
	for _, conn := range connStats {
		err := fillNetworkRelationCache(cfg.HostName, c.cache, conn, now.Add(-5*time.Minute).Unix(), now.Unix())
		assert.NoError(t, err)
	}

	// fill in the procs in the lastProcState map to get process create time for the connection mapping
	Process.lastProcState = map[int32]*model.Process{
		1: {Pid: 1, CreateTime: now.Add(-5 * time.Minute).Unix()},
		2: {Pid: 2, CreateTime: now.Add(-5 * time.Minute).Unix()},
		3: {Pid: 3, CreateTime: now.Add(-5 * time.Minute).Unix()},
		// pid 4 filtered by process blacklisting, so we expect no connections for pid 4
	}

	connections, _ := c.formatConnections(cfg, connStats, 15*time.Second, nil)

	assert.Len(t, connections, 3)

	pids := make([]int32, 0)
	for _, conn := range connections {
		pids = append(pids, conn.Pid)
	}

	assert.NotContains(t, pids, 4)
}

func TestNetworkConnectionNamespaceKubernetes(t *testing.T) {
	testClusterName := "test-cluster"
	cfg := config.NewDefaultAgentConfig()
	cfg.ClusterName = testClusterName

	now := time.Now()

	c := &ConnectionsCheck{
		buf:   new(bytes.Buffer),
		cache: NewNetworkRelationCache(cfg.NetworkRelationCacheDurationMin),
	}

	// create the connection stats
	connStats := []network.ConnectionStats{
		makeProcessConnection(1, "10.0.0.1", "10.0.0.2", 12345, 8080),
		makeProcessConnection(2, "10.0.0.1", "10.0.0.3", 12346, 8080),
		makeProcessConnection(3, "10.0.0.1", "10.0.0.4", 12347, 8080),
		makeProcessConnection(4, "10.0.0.1", "10.0.0.5", 12348, 8080),
	}

	// fill in the relation cache
	for _, conn := range connStats {
		namespace := formatNamespace(cfg.ClusterName, cfg.HostName, conn)
		err := fillNetworkRelationCache(namespace, c.cache, conn, now.Add(-5*time.Minute).Unix(), now.Unix())
		assert.NoError(t, err)
	}

	// fill in the procs in the lastProcState map to get process create time for the connection mapping
	Process.lastProcState = map[int32]*model.Process{
		1: {Pid: 1, CreateTime: now.Add(-5 * time.Minute).Unix()},
		2: {Pid: 2, CreateTime: now.Add(-5 * time.Minute).Unix()},
		3: {Pid: 3, CreateTime: now.Add(-5 * time.Minute).Unix()},
		4: {Pid: 4, CreateTime: now.Add(-5 * time.Minute).Unix()},
	}

	connections, _ := c.formatConnections(cfg, connStats, 15*time.Second, nil)

	assert.Len(t, connections, 4)
	for _, c := range connections {
		assert.Contains(t, c.Namespace, testClusterName)
	}

	// clear the changes to Process.lastProcState
	Process.lastProcState = make(map[int32]*model.Process, 0)
}

func TestRelationCache(t *testing.T) {
	cfg := config.NewDefaultAgentConfig()
	cfg.ShortLivedNetworkRelationQualifierSecs = 500 * time.Millisecond
	cfg.NetworkRelationCacheDurationMin = 600 * time.Millisecond

	now := time.Now()
	c := &ConnectionsCheck{
		buf:   new(bytes.Buffer),
		cache: NewNetworkRelationCache(cfg.NetworkRelationCacheDurationMin),
	}

	// create the connection stats
	connStats := []network.ConnectionStats{
		makeProcessConnection(1, "10.0.0.1", "10.0.0.2", 12345, 8080),
		makeProcessConnection(2, "10.0.0.1", "10.0.0.3", 12346, 8080),
		makeProcessConnection(3, "10.0.0.1", "10.0.0.4", 12347, 8080),
		makeProcessConnection(4, "10.0.0.1", "10.0.0.5", 12348, 8080),
	}

	// fill in the procs in the lastProcState map to get process create time for the connection mapping
	Process.lastProcState = map[int32]*model.Process{
		1: {Pid: 1, CreateTime: now.Add(-5 * time.Minute).Unix()},
		2: {Pid: 2, CreateTime: now.Add(-5 * time.Minute).Unix()},
		3: {Pid: 3, CreateTime: now.Add(-5 * time.Minute).Unix()},
		4: {Pid: 4, CreateTime: now.Add(-5 * time.Minute).Unix()},
	}

	// assert an empty cache.
	assert.Zero(t, c.cache.ItemCount(), "Cache should be empty before running")

	// first run on an empty cache; expect no process, but cache should be filled in now.
	firstRun, _ := c.formatConnections(cfg, connStats, 15*time.Second, nil)
	assert.Zero(t, len(firstRun), "Connections should be empty when the cache is not present")
	assert.Equal(t, 4, c.cache.ItemCount(), "Cache should contain 4 elements")

	// wait for cfg.ShortLivedNetworkRelationQualifierSecs duration
	time.Sleep(cfg.ShortLivedNetworkRelationQualifierSecs)

	// second run with filled in cache; expect all processes.
	secondRun, _ := c.formatConnections(cfg, connStats, 10*time.Second, nil)
	assert.Equal(t, 4, len(secondRun), "Connections should contain 4 elements")
	assert.Equal(t, 4, c.cache.ItemCount(), "Cache should contain 4 elements")

	// delete last connection from the connection stats slice, expect it to be excluded from the connection list, but not the cache
	connStats = connStats[:len(connStats)-1]
	thirdRun, _ := c.formatConnections(cfg, connStats, 5*time.Second, nil)
	assert.Equal(t, 3, len(thirdRun), "Connections should contain 3 elements")
	assert.Equal(t, 4, c.cache.ItemCount(), "Cache should contain 4 elements")

	// wait for cfg.NetworkRelationCacheDurationMin + a 250 Millisecond buffer to allow the cache expiration to complete
	time.Sleep(cfg.NetworkRelationCacheDurationMin + 250*time.Millisecond)
	assert.Zero(t, c.cache.ItemCount(), "Cache should be empty again")

	c.cache.Flush()
}

const (
	PID1CONN1SEND1 = uint64(1234)
	PID1CONN1RECV1 = uint64(123)
	PID1CONN2SEND1 = uint64(4321)
	PID1CONN2RECV1 = uint64(1432)
	PID2CONN1SEND1 = uint64(1324)
	PID2CONN1RECV1 = uint64(2132)

	PID1CONN1SEND2 = uint64(12340)
	PID1CONN1RECV2 = uint64(1230)
	PID1CONN2SEND2 = uint64(43210)
	PID1CONN2RECV2 = uint64(14320)
	PID2CONN1SEND2 = uint64(13240)
	PID2CONN1RECV2 = uint64(21320)

	PID1CONN1SEND3 = uint64(123400)
	PID1CONN1RECV3 = uint64(12300)
	PID1CONN2SEND3 = uint64(432100)
	PID1CONN2RECV3 = uint64(143200)
	PID2CONN1SEND3 = uint64(132400)
	PID2CONN1RECV3 = uint64(213200)

	PID1CONN1SEND4 = uint64(1234)
	PID1CONN1RECV4 = uint64(123)
	PID1CONN2SEND4 = uint64(4321)
	PID1CONN2RECV4 = uint64(1432)
	PID2CONN1SEND4 = uint64(1324)
	PID2CONN1RECV4 = uint64(2132)

	TIME2                = float32(10)
	PID1CONN1SEND2EXPECT = float32(PID1CONN1SEND2-PID1CONN1SEND1) / TIME2
	PID1CONN2SEND2EXPECT = float32(PID1CONN2SEND2-PID1CONN2SEND1) / TIME2
	PID2CONN1SEND2EXPECT = float32(PID2CONN1SEND2-PID2CONN1SEND1) / TIME2

	PID1CONN1RECV2EXPECT = float32(PID1CONN1RECV2-PID1CONN1RECV1) / TIME2
	PID1CONN2RECV2EXPECT = float32(PID1CONN2RECV2-PID1CONN2RECV1) / TIME2
	PID2CONN1RECV2EXPECT = float32(PID2CONN1RECV2-PID2CONN1RECV1) / TIME2
)

func TestRelationCacheOrdering(t *testing.T) {
	cfg := config.NewDefaultAgentConfig()
	cfg.ShortLivedNetworkRelationQualifierSecs = 500 * time.Millisecond
	cfg.NetworkRelationCacheDurationMin = 600 * time.Millisecond

	now := time.Now()
	c := &ConnectionsCheck{
		buf:   new(bytes.Buffer),
		cache: NewNetworkRelationCache(cfg.NetworkRelationCacheDurationMin),
	}

	// create the connection stats
	connStats := []network.ConnectionStats{
		makeProcessConnection(1, "10.0.0.1", "10.0.0.2", 12345, 8080),
		makeProcessConnection(1, "10.0.0.1", "10.0.0.2", 12346, 8080),
		makeProcessConnection(2, "10.0.0.1", "10.0.0.3", 12347, 8080),
		makeProcessConnection(3, "10.0.0.1", "10.0.0.4", 12348, 8080),
	}

	connStats = []network.ConnectionStats{
		amendConnectionStats(connStats[0], PID1CONN1SEND1, PID1CONN1RECV1),
		amendConnectionStats(connStats[1], PID1CONN2SEND1, PID1CONN2RECV1),
		amendConnectionStats(connStats[2], PID2CONN1SEND1, PID2CONN1RECV1),
		connStats[3],
	}

	// fill in the procs in the lastProcState map to get process create time for the connection mapping
	Process.lastProcState = map[int32]*model.Process{
		1: {Pid: 1, CreateTime: now.Add(-5 * time.Minute).Unix()},
		2: {Pid: 2, CreateTime: now.Add(-5 * time.Minute).Unix()},
		3: {Pid: 3, CreateTime: now.Add(-5 * time.Minute).Unix()},
		4: {Pid: 4, CreateTime: now.Add(-5 * time.Minute).Unix()},
	}

	// first run on an empty cache; expect no process, but cache should be filled in now.
	c.formatConnections(cfg, connStats, 15*time.Second, nil)

	connStats = []network.ConnectionStats{
		amendConnectionStats(connStats[0], PID1CONN1SEND2, PID1CONN1RECV2),
		amendConnectionStats(connStats[1], PID1CONN2SEND2, PID1CONN2RECV2),
		amendConnectionStats(connStats[2], PID2CONN1SEND2, PID2CONN1RECV2),
		connStats[3],
	}

	// wait for cfg.ShortLivedNetworkRelationQualifierSecs duration
	time.Sleep(cfg.ShortLivedNetworkRelationQualifierSecs)

	// second run with filled in cache; expect all processes.
	secondRun, _ := c.formatConnections(cfg, connStats, time.Duration(TIME2)*time.Second, nil)

	assert.Equal(t, PID1CONN1SEND2EXPECT, secondRun[0].BytesSentPerSecond, "BytesSentPerSecond")
	assert.Equal(t, PID1CONN2SEND2EXPECT, secondRun[1].BytesSentPerSecond, "BytesSentPerSecond")
	assert.Equal(t, PID2CONN1SEND2EXPECT, secondRun[2].BytesSentPerSecond, "BytesSentPerSecond")

	assert.Equal(t, PID1CONN1RECV2EXPECT, secondRun[0].BytesReceivedPerSecond, "BytesReceivedPerSecond")
	assert.Equal(t, PID1CONN2RECV2EXPECT, secondRun[1].BytesReceivedPerSecond, "BytesReceivedPerSecond")
	assert.Equal(t, PID2CONN1RECV2EXPECT, secondRun[2].BytesReceivedPerSecond, "BytesReceivedPerSecond")

	c.cache.Flush()
}

func TestRelationShortLivedFiltering(t *testing.T) {
	cfg := config.NewDefaultAgentConfig()
	lastRun := time.Now().Add(-5 * time.Second)
	now := time.Now()
	// create the connection stats
	connStats := []network.ConnectionStats{
		makeProcessConnection(1, "10.0.0.1", "10.0.0.2", 12345, 8080),
	}

	// fill in the procs in the lastProcState map to get process create time for the connection mapping
	Process.lastProcState = map[int32]*model.Process{
		1: {Pid: 1, CreateTime: now.Add(-5 * time.Minute).Unix()},
	}

	for _, tc := range []struct {
		name                             string
		prepCache                        func(c *NetworkRelationCache)
		expected                         bool
		networkRelationShortLivedEnabled bool
	}{
		{
			name: fmt.Sprintf("Should not filter a relation that has been observed longer than the short-lived qualifier "+
				"duration: %d", cfg.ShortLivedProcessQualifierSecs),
			prepCache: func(c *NetworkRelationCache) {
				err := fillNetworkRelationCache(cfg.HostName, c, connStats[0], lastRun.Add(-5*time.Minute).Unix(), lastRun.Unix())
				assert.NoError(t, err)
			},
			expected:                         true,
			networkRelationShortLivedEnabled: true,
		},
		{
			name: fmt.Sprintf("Should not filter a similar relation that has been observed longer than the short-lived qualifier "+
				"duration: %d", cfg.ShortLivedProcessQualifierSecs),
			prepCache: func(c *NetworkRelationCache) {
				// use a "similar" connection; thus we observed a similar connection in the previous run
				conn := makeProcessConnection(1, "10.0.0.1", "10.0.0.2", 54321, 8080)
				err := fillNetworkRelationCache(cfg.HostName, c, conn, lastRun.Add(-5*time.Minute).Unix(), lastRun.Unix())
				assert.NoError(t, err)
			},
			expected:                         true,
			networkRelationShortLivedEnabled: true,
		},
		{
			name: fmt.Sprintf("Should filter a relation that has not been observed longer than the short-lived qualifier "+
				"duration: %d", cfg.ShortLivedProcessQualifierSecs),
			prepCache: func(c *NetworkRelationCache) {
				err := fillNetworkRelationCache(cfg.HostName, c, connStats[0], lastRun.Add(-5*time.Second).Unix(), lastRun.Unix())
				assert.NoError(t, err)
			},
			expected:                         false,
			networkRelationShortLivedEnabled: true,
		},
		{
			name: fmt.Sprintf("Should not filter a relation when the networkRelationShortLivedEnabled is set to false"),
			prepCache: func(c *NetworkRelationCache) {
				err := fillNetworkRelationCache(cfg.HostName, c, connStats[0], lastRun.Add(-5*time.Second).Unix(), lastRun.Unix())
				assert.NoError(t, err)
			},
			expected:                         true,
			networkRelationShortLivedEnabled: false,
		},
	} {

		t.Run(tc.name, func(t *testing.T) {
			cfg.EnableShortLivedNetworkRelationFilter = tc.networkRelationShortLivedEnabled

			// Connections Check
			c := &ConnectionsCheck{
				buf:   new(bytes.Buffer),
				cache: NewNetworkRelationCache(cfg.NetworkRelationCacheDurationMin),
			}
			// fill in the relation cache
			tc.prepCache(c.cache)

			connections, _ := c.formatConnections(cfg, connStats, time.Now().Sub(lastRun), nil)
			var rIDs []string
			for _, conn := range connections {
				rIDs = append(rIDs, conn.ConnectionIdentifier)
			}

			conn := connStats[0]
			relationID, err := CreateNetworkRelationIdentifier(cfg.HostName, conn)
			assert.NoError(t, err)

			if tc.expected {
				assert.Len(t, connections, 1, "The connection should be present in the returned payload for the Connection Check")
				assert.Contains(t, rIDs, relationID, "%s should not be filtered from the relation identifiers for the Connection Check", relationID)
			} else {
				assert.Len(t, connections, 0, "The connection should be filtered in the returned payload for the Connection Check")
				assert.NotContains(t, rIDs, relationID, "%s should be filtered from the relation identifiers for the Connection Check", relationID)
			}

			c.cache.Flush()
		})
	}
}

func TestFormatNamespace(t *testing.T) {
	assert.Equal(t, "", formatNamespace("", "h", makeProcessConnection(1, "10.0.0.1", "10.0.0.2", 12345, 8080)))
	assert.Equal(t, "c", formatNamespace("c", "h", makeProcessConnection(1, "10.0.0.1", "10.0.0.2", 12345, 8080)))
	assert.Equal(t, "c", formatNamespace("c", "h", makeProcessConnection(1, "127.0.0.1", "10.0.0.2", 12345, 8080)))
	assert.Equal(t, "c", formatNamespace("c", "h", makeProcessConnection(1, "10.0.0.1", "127.0.0.1", 12345, 8080)))
	assert.Equal(t, "c:h:1", formatNamespace("c", "h", makeProcessConnection(1, "127.0.0.1", "127.0.0.1", 12345, 8080)))
	assert.Equal(t, "c:h", formatNamespace("c", "h", makeConnectionStatsNoNs(1, "127.0.0.1", "127.0.0.1", 12345, 8080)))
}

func fillNetworkRelationCache(hostname string, c *NetworkRelationCache, conn network.ConnectionStats, firstObserved, lastObserved int64) error {
	relationID, err := CreateNetworkRelationIdentifier(hostname, conn)
	if err != nil {
		return err
	}

	cachedRelation := &NetworkRelationCacheItem{
		FirstObserved: firstObserved,
	}
	c.cache.Set(relationID, cachedRelation, cache.DefaultExpiration)
	return nil
}

func TestFormatMetricsEmpty(t *testing.T) {
	metrics := aggregateHTTPStats(nil, 1*time.Second, true)
	assert.Len(t, metrics, 0)
}

func sortConnectionMetrics(metrics []*model.ConnectionMetric) {
	sort.Slice(metrics, func(i, j int) bool {
		if cmp := strings.Compare(metrics[i].Name, metrics[j].Name); cmp != 0 {
			return cmp < 0
		}
		if cmp := strings.Compare(metrics[i].Tags[httpStatusCodeTag], metrics[j].Tags[httpStatusCodeTag]); cmp != 0 {
			return cmp < 0
		}
		if cmp := strings.Compare(metrics[i].Tags[httpMethodTag], metrics[j].Tags[httpMethodTag]); cmp != 0 {
			// sort backwards to have empty method last (empty means overall aggregation)
			return cmp > 0
		}
		if cmp := strings.Compare(metrics[i].Tags[httpPathTag], metrics[j].Tags[httpPathTag]); cmp != 0 {
			return cmp < 0
		}
		return false
	})
}

func TestHTTPAggregation_SingleReq(t *testing.T) {

	conn1req1 := http.NewKey(
		util.AddressFromString("10.0.0.1"), util.AddressFromString("192.168.1.1"), 12345, 80,
		"/page", http.MethodGet)

	conn1Key := getConnectionKeyForStats(conn1req1)

	metrics := aggregateHTTPStats(map[http.Key]http.RequestStats{
		conn1req1: {
			{},
			{
				Count:              1,
				FirstLatencySample: 100,
			},
			{},
			{
				Count:     4,
				Latencies: makeDDSketch(2, 4, 6, 8),
			},
			{},
		},
	}, 2*time.Second, true)

	assert.Len(t, metrics, 1)
	conn1Metrics := metrics[conn1Key]
	assert.NotNil(t, conn1Metrics)

	sortConnectionMetrics(conn1Metrics)

	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[0], "1xx", "GET", "/page", 0)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[1], "1xx", "", "", 0)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[2], "2xx", "GET", "/page", 1.0/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[3], "2xx", "", "", 1.0/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[4], "3xx", "GET", "/page", 0)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[5], "3xx", "", "", 0)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[6], "4xx", "GET", "/page", 4/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[7], "4xx", "", "", 4/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[8], "5xx", "GET", "/page", 0)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[9], "5xx", "", "", 0)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[10], "any", "GET", "/page", 5.0/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[11], "any", "", "", 5.0/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[12], "success", "GET", "/page", 1.0/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[13], "success", "", "", 1.0/2)

	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[14], "1xx", "GET", "/page", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[15], "1xx", "", "", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[16], "2xx", "GET", "/page", 100, 100, 1)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[17], "2xx", "", "", 100, 100, 1)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[18], "3xx", "GET", "/page", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[19], "3xx", "", "", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[20], "4xx", "GET", "/page", 2, 8, 4)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[21], "4xx", "", "", 2, 8, 4)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[22], "5xx", "GET", "/page", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[23], "5xx", "", "", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[24], "any", "GET", "/page", 2, 100, 5)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[25], "any", "", "", 2, 100, 5)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[26], "success", "GET", "/page", 100, 100, 1)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[27], "success", "", "", 100, 100, 1)

	assert.Len(t, conn1Metrics, 28)
}

func TestHTTPAggregation_MultipleReq(t *testing.T) {

	conn1req1 := http.NewKey(
		util.AddressFromString("10.0.0.1"), util.AddressFromString("192.168.1.1"), 12345, 80,
		"/page", http.MethodGet)
	conn1req2 := http.NewKey(
		util.AddressFromString("10.0.0.1"), util.AddressFromString("192.168.1.1"), 12345, 80,
		"/page", http.MethodPost)
	conn1req3 := http.NewKey(
		util.AddressFromString("10.0.0.1"), util.AddressFromString("192.168.1.1"), 12345, 80,
		"/otherpath", http.MethodGet)
	conn2req4 := http.NewKey(
		util.AddressFromString("10.0.0.1"), util.AddressFromString("2.3.4.5"), 12345, 80,
		"/page", http.MethodGet)
	conn2req5 := http.NewKey(
		util.AddressFromString("10.0.0.1"), util.AddressFromString("2.3.4.5"), 12345, 80,
		"/page", http.MethodPost)

	conn1Key := getConnectionKeyForStats(conn1req1)
	assert.Equal(t, conn1Key, getConnectionKeyForStats(conn1req2))
	assert.Equal(t, conn1Key, getConnectionKeyForStats(conn1req3))
	conn2Key := getConnectionKeyForStats(conn2req4)
	assert.Equal(t, conn2Key, getConnectionKeyForStats(conn2req5))
	assert.NotEqual(t, conn1Key, conn2Key)

	metrics := aggregateHTTPStats(map[http.Key]http.RequestStats{
		conn1req2: { // post /page
			{},
			{},
			{
				Count:              1,
				FirstLatencySample: 90000,
			},
			{},
			{
				Count:     4,
				Latencies: makeDDSketch(60000, 90000, 120000, 60000),
			},
		},
		conn1req3: { // get /otherpath
			{
				Count:              1,
				FirstLatencySample: 60000,
			},
			{
				Count:     2,
				Latencies: makeDDSketch(90000, 120000),
			},
			{
				Count:     4,
				Latencies: makeDDSketch(12000, 90000, 120000, 60000),
			},
			{
				Count:     5,
				Latencies: makeDDSketch(60000, 90000, 120000, 60000, 90000),
			},
			{
				Count:              1,
				FirstLatencySample: 180000,
			},
		},
		conn1req1: { // get /page
			{},
			{
				Count:              1,
				FirstLatencySample: 120000,
			},
			{},
			{
				Count:     3,
				Latencies: makeDDSketch(120000, 60000, 90000),
			},
			{},
		},
		conn2req4: { // get /page
			{},
			{
				Count:              1,
				FirstLatencySample: 6000,
			},
			{},
			{
				Count:     2,
				Latencies: makeDDSketch(12000, 24000),
			},
			{},
		},
	}, 2*time.Second, true)

	assert.Equal(t, len(metrics), 2)
	conn1Metrics := metrics[conn1Key]
	assert.NotNil(t, conn1Metrics)
	conn2Metrics := metrics[conn2Key]
	assert.NotNil(t, conn2Metrics)

	sortConnectionMetrics(conn1Metrics)
	sortConnectionMetrics(conn2Metrics)

	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[0], "1xx", "POST", "/page", 0)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[1], "1xx", "GET", "/otherpath", 1.0/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[2], "1xx", "GET", "/page", 0)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[3], "1xx", "", "", (0+1.0+0)/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[4], "2xx", "POST", "/page", 0)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[5], "2xx", "GET", "/otherpath", 2.0/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[6], "2xx", "GET", "/page", 1.0/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[7], "2xx", "", "", (0+2.0+1.0)/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[8], "3xx", "POST", "/page", 1.0/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[9], "3xx", "GET", "/otherpath", 4.0/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[10], "3xx", "GET", "/page", 0)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[11], "3xx", "", "", (1.0+4.0+0)/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[12], "4xx", "POST", "/page", 0)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[13], "4xx", "GET", "/otherpath", 5.0/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[14], "4xx", "GET", "/page", 3.0/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[15], "4xx", "", "", (0+5.0+3.0)/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[16], "5xx", "POST", "/page", 4.0/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[17], "5xx", "GET", "/otherpath", 1.0/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[18], "5xx", "GET", "/page", 0)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[19], "5xx", "", "", (4.0+1.0+0)/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[20], "any", "POST", "/page", (0+0+1.0+0+4.0)/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[21], "any", "GET", "/otherpath", (1.0+2.0+4.0+5.0+1.0)/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[22], "any", "GET", "/page", (0+1.0+0+3.0+0)/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[23], "any", "", "", ((0+0+1.0+0+4.0)+(1.0+2.0+4.0+5.0+1.0)+(0+1.0+0+3.0+0))/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[24], "success", "POST", "/page", (0+0+1.0)/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[25], "success", "GET", "/otherpath", (1.0+2.0+4.0)/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[26], "success", "GET", "/page", (0+1.0+0)/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[27], "success", "", "", ((0+0+1.0)+(1.0+2.0+4.0)+(0+1.0+0))/2)

	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[28], "1xx", "POST", "/page", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[29], "1xx", "GET", "/otherpath", 60000, 60000, 1)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[30], "1xx", "GET", "/page", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[31], "1xx", "", "", 60000, 60000, 1)

	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[32], "2xx", "POST", "/page", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[33], "2xx", "GET", "/otherpath", 90000, 120000, 2)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[34], "2xx", "GET", "/page", 120000, 120000, 1)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[35], "2xx", "", "", 90000, 120000, 3)

	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[36], "3xx", "POST", "/page", 90000, 90000, 1)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[37], "3xx", "GET", "/otherpath", 12000, 120000, 4)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[38], "3xx", "GET", "/page", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[39], "3xx", "", "", 12000, 120000, 5)

	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[40], "4xx", "POST", "/page", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[41], "4xx", "GET", "/otherpath", 60000, 120000, 5)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[42], "4xx", "GET", "/page", 60000, 120000, 3)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[43], "4xx", "", "", 60000, 120000, 8)

	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[44], "5xx", "POST", "/page", 60000, 120000, 4)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[45], "5xx", "GET", "/otherpath", 180000, 180000, 1)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[46], "5xx", "GET", "/page", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[47], "5xx", "", "", 60000, 180000, 5)

	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[48], "any", "POST", "/page", 60000, 120000, 5)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[49], "any", "GET", "/otherpath", 12000, 180000, 13)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[50], "any", "GET", "/page", 60000, 120000, 4)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[51], "any", "", "", 12000, 180000, 22)

	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[52], "success", "POST", "/page", 90000, 90000, 1)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[53], "success", "GET", "/otherpath", 12000, 120000, 7)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[54], "success", "GET", "/page", 120000, 120000, 1)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[55], "success", "", "", 12000, 120000, 9)

	// no more metrics for conn1
	assert.Equal(t, 56, len(conn1Metrics))

	// for the second connection we just check the number of metrics
	// and be happy that it didn't influence the first connection's metrics
	// number calculated as product of
	//  * 1+1 - specific route and aggregated
	//  * 5+2 - specific status code groups + any + success
	//  * 2 - rate + response time
	assert.Equal(t, (1+1)*(5+2)*2, len(conn2Metrics))
}

func TestHTTPAggregation_SingleReq_NoPath(t *testing.T) {

	conn1req1 := http.NewKey(
		util.AddressFromString("10.0.0.1"), util.AddressFromString("192.168.1.1"), 12345, 80,
		"/page", http.MethodGet)

	conn1Key := getConnectionKeyForStats(conn1req1)

	metrics := aggregateHTTPStats(map[http.Key]http.RequestStats{
		conn1req1: {
			{},
			{
				Count:              1,
				FirstLatencySample: 100,
			},
			{},
			{
				Count:     4,
				Latencies: makeDDSketch(2, 4, 6, 8),
			},
			{},
		},
	}, 2*time.Second, false)

	assert.Len(t, metrics, 1)
	conn1Metrics := metrics[conn1Key]
	assert.NotNil(t, conn1Metrics)

	sortConnectionMetrics(conn1Metrics)

	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[0], "1xx", "", "", 0)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[1], "2xx", "", "", 1.0/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[2], "3xx", "", "", 0)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[3], "4xx", "", "", 4/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[4], "5xx", "", "", 0)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[5], "any", "", "", 5.0/2)
	assertHTTPRequestsPerSecondConnectionMetric(t, conn1Metrics[6], "success", "", "", 1.0/2)

	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[7], "1xx", "", "", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[8], "2xx", "", "", 100, 100, 1)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[9], "3xx", "", "", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[10], "4xx", "", "", 2, 8, 4)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[11], "5xx", "", "", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[12], "any", "", "", 2, 100, 5)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[13], "success", "", "", 100, 100, 1)

	assert.Len(t, conn1Metrics, 14)
}

func assertHTTPResponseTimeConnectionMetric(t *testing.T, formattedMetric *model.ConnectionMetric, statusCode, method, path string, min, max, total int) {
	assert.Equal(t, "http_response_time_seconds", formattedMetric.Name)
	expectedTags := map[string]string{
		"code": statusCode,
	}
	if path != "" || method != "" {
		expectedTags["path"] = path
		expectedTags["method"] = method
	}
	codeIsOk := assert.Equal(t, expectedTags, formattedMetric.Tags)
	if codeIsOk {
		actualSketch, err := ddsketch.FromProto(formattedMetric.Value.GetHistogram())
		assert.NoError(t, err)
		assert.Equal(t, total, int(actualSketch.GetCount()), "Total doesn't match for status code `%s`", statusCode)
		var actualMin, actualMax float64
		if int(actualSketch.GetCount()) != 0 {
			actualMin, err = actualSketch.GetMinValue()
			assert.NoError(t, err)
			actualMax, err = actualSketch.GetMaxValue()
			assert.NoError(t, err)
		}
		if min == 0 {
			assert.Equal(t, 0.0, actualMin, "Min doesn't match for status code `%s`", statusCode)
		} else {
			// We use a 1% error margin to account for the fact that the sketch is not exact
			assert.InEpsilon(t, min, actualMin, 0.01, "Min doesn't match for status code `%s`", statusCode)
		}
		if max == 0 {
			assert.Equal(t, 0.0, actualMax, "Max doesn't match for status code `%s`", statusCode)
		} else {
			// We use a 1% error margin to account for the fact that the sketch is not exact
			assert.InEpsilon(t, max, actualMax, 0.01, "Max doesn't match for status code `%s`", statusCode)
		}
	}
}

func assertHTTPRequestsPerSecondConnectionMetric(t *testing.T, formattedMetric *model.ConnectionMetric, statusCode, method, path string, expectedRate float64) {
	assertHttpRequestsBaseMetric(t, "http_requests_per_second", formattedMetric, statusCode, method, path, expectedRate)
}

func assertHttpRequestsBaseMetric(t *testing.T, expectedMetric string, formattedMetric *model.ConnectionMetric, statusCode, method, path string, expectedValue float64) {
	assert.Equal(t, expectedMetric, formattedMetric.Name)
	expectedTags := map[string]string{
		"code": statusCode,
	}
	if path != "" || method != "" {
		expectedTags["path"] = path
		expectedTags["method"] = method
	}
	codeIsOk := assert.Equal(t, expectedTags, formattedMetric.Tags)
	if codeIsOk {
		assert.Equal(t, expectedValue, formattedMetric.Value.GetNumber())
	}
}

func assertHTTPRequestsCountMetric(t *testing.T, formattedMetric *model.ConnectionMetric, statusCode, method, path string, expectedCount float64) {
	assertHttpRequestsBaseMetric(t, "http_requests_count", formattedMetric, statusCode, method, path, expectedCount)
}

func makeDDSketch(responseTimes ...float64) *ddsketch.DDSketch {
	testDDSketch, _ := ddsketch.NewDefaultDDSketch(0.01)
	for _, rt := range responseTimes {
		_ = testDDSketch.Add(rt)
	}
	return testDDSketch
}
