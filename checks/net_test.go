package checks

import (
	"bytes"
	"fmt"
	"math"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/http"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/kubelet"
	"github.com/DataDog/sketches-go/ddsketch"
	"github.com/pborman/uuid"

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
		podsIndex := &connectionsPodsIndex{
			pods:        map[string]*model.Pod{},
			pidToPodUID: map[int32]string{},
		}
		chunks := batchConnections(cfg, 0, tc.cur, podsIndex, 10000000)

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
	stats.Last.SentBytes = sent - stats.Last.SentBytes
	stats.Last.RecvBytes = received - stats.Last.RecvBytes
	return stats
}

func TestNetworkRelationCacheExpiration(t *testing.T) {
	cache := NewNetworkRelationCache(100 * time.Millisecond)
	cfg := &config.AgentConfig{HostName: "example.org"}
	addStats := func(conns ...network.ConnectionStats) {
		for _, conn := range conns {
			relationID := CreateNetworkRelationIdentifier(cfg, conn)
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
		err := fillNetworkRelationCache(cfg, c.cache, conn, now.Add(-5*time.Minute).Unix(), now.Unix())
		assert.NoError(t, err)
	}

	// fill in the procs in the lastProcState map to get process create time for the connection mapping
	Process.lastProcState = map[int32]*model.Process{
		1: {Pid: 1, CreateTime: now.Add(-5 * time.Minute).Unix()},
		2: {Pid: 2, CreateTime: now.Add(-5 * time.Minute).Unix()},
		3: {Pid: 3, CreateTime: now.Add(-5 * time.Minute).Unix()},
		// pid 4 filtered by process blacklisting, so we expect no connections for pid 4
	}

	connections, _ := c.formatConnections(cfg, connStats, nil, nil, nil, nil)

	// Connection will be reported but with pid 0
	assert.Len(t, connections, 4)

	pids := make([]int32, 0)
	for _, conn := range connections {
		pids = append(pids, conn.Pid)
	}

	assert.NotContains(t, pids, 4)
	assert.Contains(t, pids, int32(0))
}

func TestPodsIndexFormatted(t *testing.T) {
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
		err := fillNetworkRelationCache(cfg, c.cache, conn, now.Add(-5*time.Minute).Unix(), now.Unix())
		assert.NoError(t, err)
	}

	// fill in the procs in the lastProcState map to get process create time for the connection mapping
	Process.lastProcState = map[int32]*model.Process{
		1: {Pid: 1, CreateTime: now.Add(-5 * time.Minute).Unix(), ContainerId: "container-id-1"},
		2: {Pid: 2, CreateTime: now.Add(-5 * time.Minute).Unix(), ContainerId: "container-id-2"},
		3: {Pid: 3, CreateTime: now.Add(-5 * time.Minute).Unix(), ContainerId: "container-id-3"},
		// pid 4 filtered by process blacklisting, so we expect no connections for pid 4
	}

	podA := &kubelet.Pod{
		Metadata: kubelet.PodMetadata{
			Namespace: "test",
			Name:      "pod-a",
			UID:       "pod-a-uid",
			Labels:    map[string]string{},
		},
	}
	podB := &kubelet.Pod{
		Metadata: kubelet.PodMetadata{
			Namespace: "test",
			Name:      "pod-b",
			UID:       "pod-b-uid",
			Labels:    map[string]string{},
		},
	}

	containerToPod := map[string]*kubelet.Pod{
		"container-id-1": podA,
		"container-id-2": podB,
		"container-id-3": podB,
	}

	expectedPodA := &model.Pod{
		Namespace: "test",
		Name:      "pod-a",
		Uid:       "pod-a-uid",
		Labels:    map[string]string{},
		Pids:      []int32{1},
	}
	expectedPodB := &model.Pod{
		Namespace: "test",
		Name:      "pod-b",
		Uid:       "pod-b-uid",
		Labels:    map[string]string{},
		Pids:      []int32{2, 3},
	}

	_, podsIndex := c.formatConnections(cfg, connStats, nil, nil, containerToPod, nil)

	assert.Len(t, podsIndex.pidToPodUID, 3)
	assert.Equal(t, "pod-a-uid", podsIndex.pidToPodUID[1])
	assert.Equal(t, "pod-b-uid", podsIndex.pidToPodUID[2])
	assert.Equal(t, "pod-b-uid", podsIndex.pidToPodUID[3])
	assert.Len(t, podsIndex.pods, 2)
	assert.Equal(t, expectedPodA, podsIndex.pods["pod-a-uid"])
	sort.Slice(podsIndex.pods["pod-b-uid"].Pids, func(i, j int) bool {
		return podsIndex.pods["pod-b-uid"].Pids[i] < podsIndex.pods["pod-b-uid"].Pids[j]
	})
	assert.Equal(t, expectedPodB, podsIndex.pods["pod-b-uid"])
}

func TestNetworkConnectionScopeKubernetes(t *testing.T) {
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
		err := fillNetworkRelationCache(cfg, c.cache, conn, now.Add(-5*time.Minute).Unix(), now.Unix())
		assert.NoError(t, err)
	}

	// fill in the procs in the lastProcState map to get process create time for the connection mapping
	Process.lastProcState = map[int32]*model.Process{
		1: {Pid: 1, CreateTime: now.Add(-5 * time.Minute).Unix()},
		2: {Pid: 2, CreateTime: now.Add(-5 * time.Minute).Unix()},
		3: {Pid: 3, CreateTime: now.Add(-5 * time.Minute).Unix()},
		4: {Pid: 4, CreateTime: now.Add(-5 * time.Minute).Unix()},
	}

	connections, _ := c.formatConnections(cfg, connStats, nil, nil, nil, nil)

	assert.Len(t, connections, 4)

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
	firstRun, _ := c.formatConnections(cfg, connStats, nil, nil, nil, nil)
	assert.Equal(t, 4, len(firstRun), "Connections should be there but pid 0")
	for _, conn := range firstRun {
		assert.Equal(t, int32(0), conn.Pid)
	}
	assert.Equal(t, 4, c.cache.ItemCount(), "Cache should contain 4 elements")

	// wait for cfg.ShortLivedNetworkRelationQualifierSecs duration
	time.Sleep(cfg.ShortLivedNetworkRelationQualifierSecs)

	// second run with filled in cache; expect all processes.
	secondRun, _ := c.formatConnections(cfg, connStats, nil, nil, nil, nil)
	assert.Equal(t, 4, len(secondRun), "Connections should contain 4 elements")
	assert.Equal(t, 4, c.cache.ItemCount(), "Cache should contain 4 elements")

	// delete last connection from the connection stats slice, expect it to be excluded from the connection list, but not the cache
	connStats = connStats[:len(connStats)-1]
	thirdRun, _ := c.formatConnections(cfg, connStats, nil, nil, nil, nil)
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

	PID1CONN1SEND2DELTA = float64(PID1CONN1SEND2 - PID1CONN1SEND1)
	PID1CONN2SEND2DELTA = float64(PID1CONN2SEND2 - PID1CONN2SEND1)
	PID2CONN1SEND2DELTA = float64(PID2CONN1SEND2 - PID2CONN1SEND1)

	PID1CONN1RECV2DELTA = float64(PID1CONN1RECV2 - PID1CONN1RECV1)
	PID1CONN2RECV2DELTA = float64(PID1CONN2RECV2 - PID1CONN2RECV1)
	PID2CONN1RECV2DELTA = float64(PID2CONN1RECV2 - PID2CONN1RECV1)
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
	c.formatConnections(cfg, connStats, nil, nil, nil, nil)

	connStats = []network.ConnectionStats{
		amendConnectionStats(connStats[0], PID1CONN1SEND2, PID1CONN1RECV2),
		amendConnectionStats(connStats[1], PID1CONN2SEND2, PID1CONN2RECV2),
		amendConnectionStats(connStats[2], PID2CONN1SEND2, PID2CONN1RECV2),
		connStats[3],
	}

	// wait for cfg.ShortLivedNetworkRelationQualifierSecs duration
	time.Sleep(cfg.ShortLivedNetworkRelationQualifierSecs)

	// second run with filled in cache; expect all processes.
	secondRun, _ := c.formatConnections(cfg, connStats, nil, nil, nil, nil)

	assert.Equal(t, PID1CONN1SEND2DELTA, getConnectionMetricNumber(t, secondRun[0].Metrics, bytesSentDelta), bytesSentDelta)
	assert.Equal(t, PID1CONN2SEND2DELTA, getConnectionMetricNumber(t, secondRun[1].Metrics, bytesSentDelta), bytesSentDelta)
	assert.Equal(t, PID2CONN1SEND2DELTA, getConnectionMetricNumber(t, secondRun[2].Metrics, bytesSentDelta), bytesSentDelta)

	assert.Equal(t, PID1CONN1RECV2DELTA, getConnectionMetricNumber(t, secondRun[0].Metrics, bytesReceivedDelta), bytesReceivedDelta)
	assert.Equal(t, PID1CONN2RECV2DELTA, getConnectionMetricNumber(t, secondRun[1].Metrics, bytesReceivedDelta), bytesReceivedDelta)
	assert.Equal(t, PID2CONN1RECV2DELTA, getConnectionMetricNumber(t, secondRun[2].Metrics, bytesReceivedDelta), bytesReceivedDelta)

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
				err := fillNetworkRelationCache(cfg, c, connStats[0], lastRun.Add(-5*time.Minute).Unix(), lastRun.Unix())
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
				err := fillNetworkRelationCache(cfg, c, conn, lastRun.Add(-5*time.Minute).Unix(), lastRun.Unix())
				assert.NoError(t, err)
			},
			expected:                         true,
			networkRelationShortLivedEnabled: true,
		},
		{
			name: fmt.Sprintf("Should filter a relation that has not been observed longer than the short-lived qualifier "+
				"duration: %d", cfg.ShortLivedProcessQualifierSecs),
			prepCache: func(c *NetworkRelationCache) {
				err := fillNetworkRelationCache(cfg, c, connStats[0], lastRun.Add(-5*time.Second).Unix(), lastRun.Unix())
				assert.NoError(t, err)
			},
			expected:                         false,
			networkRelationShortLivedEnabled: true,
		},
		{
			name: fmt.Sprintf("Should not filter a relation when the networkRelationShortLivedEnabled is set to false"),
			prepCache: func(c *NetworkRelationCache) {
				err := fillNetworkRelationCache(cfg, c, connStats[0], lastRun.Add(-5*time.Second).Unix(), lastRun.Unix())
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

			connections, _ := c.formatConnections(cfg, connStats, nil, nil, nil, nil)

			var rIDs []string
			for _, conn := range connStats {
				rIDs = append(rIDs, CreateNetworkRelationIdentifier(cfg, conn))
			}

			conn := connStats[0]
			relationID := CreateNetworkRelationIdentifier(cfg, conn)

			if tc.expected {
				assert.Len(t, connections, 1, "The connection should be present in the returned payload for the Connection Check")
				assert.Contains(t, rIDs, relationID, "%s should not be filtered from the relation identifiers for the Connection Check", relationID)
			} else {
				assert.Len(t, connections, 1, "The connection should be filtered in the returned payload for the Connection Check")
				assert.Equal(t, int32(0), connections[0].Pid)
			}

			c.cache.Flush()
		})
	}
}

func TestMakeAddressScope(t *testing.T) {
	cfg := &config.AgentConfig{ClusterName: "c", HostName: "h"}

	assert.Equal(t, "", makeAddressScope(cfg, 1, util.AddressFromString("8.8.8.8")))
	assert.Equal(t, "c", makeAddressScope(cfg, 1, util.AddressFromString("10.0.0.2")))
	assert.Equal(t, "c:h:1", makeAddressScope(cfg, 1, util.AddressFromString("127.0.0.1")))
	assert.Equal(t, "c:h", makeAddressScope(cfg, 0, util.AddressFromString("127.0.0.1")))
}

func fillNetworkRelationCache(cfg *config.AgentConfig, c *NetworkRelationCache, conn network.ConnectionStats, firstObserved, _ int64) error {
	relationID := CreateNetworkRelationIdentifier(cfg, conn)

	cachedRelation := &NetworkRelationCacheItem{
		FirstObserved: firstObserved,
	}
	c.cache.Set(relationID, cachedRelation, cache.DefaultExpiration)
	return nil
}

func TestFormatMetricsEmpty(t *testing.T) {
	metrics := aggregateHTTPStats(nil, true)
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

func getConnectionMetricNumber(t *testing.T, metrics []*model.ConnectionMetric, name metricName) float64 {
	// Can be replaced with https://pkg.go.dev/golang.org/x/exp/slices#IndexFunc in go 1.18
	for _, v := range metrics {
		if v.Name == string(name) {
			return v.Value.GetNumber()
		}
	}

	t.Fatalf("Could not find %s among %v", name, metrics)
	return 0
}

func msToNs(ms float64) float64 {
	return ms * 1000000
}

func TestHTTPAggregation_SingleReq(t *testing.T) {

	conn1req1 := http.NewKey(
		util.AddressFromString("10.0.0.1"), util.AddressFromString("192.168.1.1"), 12345, 80,
		[]byte("/page"), true, http.MethodGet, 0)

	conn1Key := getConnectionKeyForHTTPStats(conn1req1)

	var stats = http.NewRequestStats(true)
	stats.AddRequest(200, msToNs(100.0), 0, nil)
	stats.AddRequest(400, msToNs(2.0), 0, nil)
	stats.AddRequest(400, msToNs(4.0), 0, nil)
	stats.AddRequest(400, msToNs(6.0), 0, nil)
	stats.AddRequest(400, msToNs(8.0), 0, nil)

	metrics := aggregateHTTPStats(map[http.Key]*http.RequestStats{
		conn1req1: stats,
	}, true)

	assert.Len(t, metrics, 1)
	conn1Metrics := metrics[conn1Key]
	assert.NotNil(t, conn1Metrics)

	sortConnectionMetrics(conn1Metrics)

	assertHTTPRequestsDeltaMetric(t, conn1Metrics[0], "1xx", "GET", "/page", 0)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[1], "1xx", "", "", 0)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[2], "2xx", "GET", "/page", 1)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[3], "2xx", "", "", 1)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[4], "3xx", "GET", "/page", 0)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[5], "3xx", "", "", 0)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[6], "4xx", "GET", "/page", 4)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[7], "4xx", "", "", 4)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[8], "5xx", "GET", "/page", 0)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[9], "5xx", "", "", 0)

	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[10], "1xx", "GET", "/page", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[11], "1xx", "", "", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[12], "2xx", "GET", "/page", 100, 100, 1)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[13], "2xx", "", "", 100, 100, 1)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[14], "3xx", "GET", "/page", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[15], "3xx", "", "", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[16], "4xx", "GET", "/page", 2, 8, 4)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[17], "4xx", "", "", 2, 8, 4)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[18], "5xx", "GET", "/page", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[19], "5xx", "", "", 0, 0, 0)

	assert.Len(t, conn1Metrics, 20)
}

func TestHTTPAggregation_MultipleReq(t *testing.T) {

	conn1req1 := http.NewKey(
		util.AddressFromString("10.0.0.1"), util.AddressFromString("192.168.1.1"), 12345, 80,
		[]byte("/page"), true, http.MethodGet, 0)
	conn1req2 := http.NewKey(
		util.AddressFromString("10.0.0.1"), util.AddressFromString("192.168.1.1"), 12345, 80,
		[]byte("/page"), true, http.MethodPost, 0)
	conn1req3 := http.NewKey(
		util.AddressFromString("10.0.0.1"), util.AddressFromString("192.168.1.1"), 12345, 80,
		[]byte("/otherpath"), true, http.MethodGet, 0)
	conn2req4 := http.NewKey(
		util.AddressFromString("10.0.0.1"), util.AddressFromString("2.3.4.5"), 12345, 80,
		[]byte("/page"), true, http.MethodGet, 0)
	conn2req5 := http.NewKey(
		util.AddressFromString("10.0.0.1"), util.AddressFromString("2.3.4.5"), 12345, 80,
		[]byte("/page"), true, http.MethodPost, 0)

	conn1Key := getConnectionKeyForHTTPStats(conn1req1)
	assert.Equal(t, conn1Key, getConnectionKeyForHTTPStats(conn1req2))
	assert.Equal(t, conn1Key, getConnectionKeyForHTTPStats(conn1req3))
	conn2Key := getConnectionKeyForHTTPStats(conn2req4)
	assert.Equal(t, conn2Key, getConnectionKeyForHTTPStats(conn2req5))
	assert.NotEqual(t, conn1Key, conn2Key)

	conn1req2Stats := http.NewRequestStats(true)
	conn1req3Stats := http.NewRequestStats(true)
	conn1req1Stats := http.NewRequestStats(true)
	conn2req4Stats := http.NewRequestStats(true)

	conn1req2Stats.AddRequest(300, msToNs(90000), 0, nil)
	conn1req2Stats.AddRequest(500, msToNs(60000), 0, nil)
	conn1req2Stats.AddRequest(500, msToNs(90000), 0, nil)
	conn1req2Stats.AddRequest(500, msToNs(120000), 0, nil)
	conn1req2Stats.AddRequest(500, msToNs(60000), 0, nil)

	conn1req3Stats.AddRequest(100, msToNs(60000), 0, nil)
	conn1req3Stats.AddRequest(200, msToNs(90000), 0, nil)
	conn1req3Stats.AddRequest(200, msToNs(120000), 0, nil)
	conn1req3Stats.AddRequest(300, msToNs(12000), 0, nil)
	conn1req3Stats.AddRequest(300, msToNs(90000), 0, nil)
	conn1req3Stats.AddRequest(300, msToNs(120000), 0, nil)
	conn1req3Stats.AddRequest(300, msToNs(60000), 0, nil)
	conn1req3Stats.AddRequest(400, msToNs(60000), 0, nil)
	conn1req3Stats.AddRequest(400, msToNs(90000), 0, nil)
	conn1req3Stats.AddRequest(400, msToNs(120000), 0, nil)
	conn1req3Stats.AddRequest(400, msToNs(60000), 0, nil)
	conn1req3Stats.AddRequest(400, msToNs(90000), 0, nil)
	conn1req3Stats.AddRequest(500, msToNs(180000), 0, nil)

	conn1req1Stats.AddRequest(200, msToNs(120000), 0, nil)
	conn1req1Stats.AddRequest(400, msToNs(120000), 0, nil)
	conn1req1Stats.AddRequest(400, msToNs(60000), 0, nil)
	conn1req1Stats.AddRequest(400, msToNs(90000), 0, nil)

	conn2req4Stats.AddRequest(200, msToNs(6000), 0, nil)
	conn2req4Stats.AddRequest(400, msToNs(12000), 0, nil)
	conn2req4Stats.AddRequest(400, msToNs(24000), 0, nil)

	metrics := aggregateHTTPStats(map[http.Key]*http.RequestStats{
		conn1req2: conn1req2Stats,
		conn1req3: conn1req3Stats,
		conn1req1: conn1req1Stats,
		conn2req4: conn2req4Stats,
	}, true)

	assert.Equal(t, len(metrics), 2)
	conn1Metrics := metrics[conn1Key]
	assert.NotNil(t, conn1Metrics)
	conn2Metrics := metrics[conn2Key]
	assert.NotNil(t, conn2Metrics)

	sortConnectionMetrics(conn1Metrics)
	sortConnectionMetrics(conn2Metrics)

	assertHTTPRequestsDeltaMetric(t, conn1Metrics[0], "1xx", "POST", "/page", 0)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[1], "1xx", "GET", "/otherpath", 1)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[2], "1xx", "GET", "/page", 0)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[3], "1xx", "", "", 1)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[4], "2xx", "POST", "/page", 0)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[5], "2xx", "GET", "/otherpath", 2)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[6], "2xx", "GET", "/page", 1)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[7], "2xx", "", "", 3)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[8], "3xx", "POST", "/page", 1)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[9], "3xx", "GET", "/otherpath", 4)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[10], "3xx", "GET", "/page", 0)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[11], "3xx", "", "", 5)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[12], "4xx", "POST", "/page", 0)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[13], "4xx", "GET", "/otherpath", 5)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[14], "4xx", "GET", "/page", 3)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[15], "4xx", "", "", 8)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[16], "5xx", "POST", "/page", 4)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[17], "5xx", "GET", "/otherpath", 1)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[18], "5xx", "GET", "/page", 0)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[19], "5xx", "", "", 5)

	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[20], "1xx", "POST", "/page", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[21], "1xx", "GET", "/otherpath", 60000, 60000, 1)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[22], "1xx", "GET", "/page", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[23], "1xx", "", "", 60000, 60000, 1)

	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[24], "2xx", "POST", "/page", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[25], "2xx", "GET", "/otherpath", 90000, 120000, 2)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[26], "2xx", "GET", "/page", 120000, 120000, 1)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[27], "2xx", "", "", 90000, 120000, 3)

	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[28], "3xx", "POST", "/page", 90000, 90000, 1)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[29], "3xx", "GET", "/otherpath", 12000, 120000, 4)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[30], "3xx", "GET", "/page", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[31], "3xx", "", "", 12000, 120000, 5)

	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[32], "4xx", "POST", "/page", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[33], "4xx", "GET", "/otherpath", 60000, 120000, 5)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[34], "4xx", "GET", "/page", 60000, 120000, 3)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[35], "4xx", "", "", 60000, 120000, 8)

	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[36], "5xx", "POST", "/page", 60000, 120000, 4)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[37], "5xx", "GET", "/otherpath", 180000, 180000, 1)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[38], "5xx", "GET", "/page", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[39], "5xx", "", "", 60000, 180000, 5)

	// no more metrics for conn1
	assert.Equal(t, 40, len(conn1Metrics))

	// for the second connection we just check the number of metrics
	// and be happy that it didn't influence the first connection's metrics
	// number calculated as product of
	//  * 1+1 - specific route and aggregated
	//  * 5 - specific status code groups
	//  * 2 - request count + response time
	assert.Equal(t, (1+1)*5*2, len(conn2Metrics))
}

func TestHTTPObservations(t *testing.T) {

	conn1req1 := http.NewKey(
		util.AddressFromString("10.0.0.1"), util.AddressFromString("192.168.1.1"), 12345, 80,
		[]byte("/page"), true, http.MethodGet, 0)
	conn1req2 := http.NewKey(
		util.AddressFromString("10.0.0.1"), util.AddressFromString("192.168.1.1"), 12345, 80,
		[]byte("/page"), true, http.MethodPost, 0)
	conn1req3 := http.NewKey(
		util.AddressFromString("10.0.0.1"), util.AddressFromString("192.168.1.1"), 12345, 80,
		[]byte("/otherpath"), true, http.MethodGet, 0)
	conn2req4 := http.NewKey(
		util.AddressFromString("10.0.0.1"), util.AddressFromString("2.3.4.5"), 12345, 80,
		[]byte("/page"), true, http.MethodGet, 0)
	conn2req5 := http.NewKey(
		util.AddressFromString("10.0.0.1"), util.AddressFromString("2.3.4.5"), 12345, 80,
		[]byte("/page"), true, http.MethodPost, 0)

	conn1Key := getConnectionKeyForHTTPStats(conn1req1)
	assert.Equal(t, conn1Key, getConnectionKeyForHTTPStats(conn1req2))
	assert.Equal(t, conn1Key, getConnectionKeyForHTTPStats(conn1req3))
	conn2Key := getConnectionKeyForHTTPStats(conn2req4)
	assert.Equal(t, conn2Key, getConnectionKeyForHTTPStats(conn2req5))
	assert.NotEqual(t, conn1Key, conn2Key)

	observations := aggregateHTTPTraceObservations([]http.TransactionObservation{
		{
			LatencyNs: msToNs(800),
			Status:    200,
			Key:       conn1req1,
			TraceId: http.TransactionTraceId{
				Id:   "traceId",
				Type: http.TraceIdRequest,
			},
		},
		{
			LatencyNs: msToNs(800),
			Status:    400,
			Key:       conn1req2,
			TraceId: http.TransactionTraceId{
				Id:   "traceId",
				Type: http.TraceIdResponse,
			},
		},
		{
			LatencyNs: msToNs(800),
			Status:    200,
			Key:       conn1req3,
			TraceId: http.TransactionTraceId{
				Id:   "0538a510-7ad2-4ef1-a852-19dd47c50090", // uuid-v4
				Type: http.TraceIdRequest,
			},
		},
		{
			LatencyNs: msToNs(800),
			Status:    501,
			Key:       conn2req4,
			TraceId: http.TransactionTraceId{
				Id:   "bd4f98f0-141a-11ee-be56-0242ac120002", // uuid-v1
				Type: http.TraceIdBoth,
			},
		},
		{
			LatencyNs: msToNs(450),
			Status:    200,
			Key:       conn2req5,
			TraceId: http.TransactionTraceId{
				Id:   "BD4f98f0-141a-11ee-be56-0242ac120002", // Some caps
				Type: http.TraceIdResponse,
			},
		},
		{
			LatencyNs: msToNs(450),
			Status:    200,
			Key:       conn2req5,
			TraceId: http.TransactionTraceId{
				Id:   "BD4f98f0-141a-11ee-be56-0242ac120002", // Some caps
				Type: http.TraceIdNone,                       // Will be filtered
			},
		},
	})

	v4trace, _ := uuid.Parse("0538a510-7ad2-4ef1-a852-19dd47c50090").MarshalBinary()
	v1trace, _ := uuid.Parse("bd4f98f0-141a-11ee-be56-0242ac120002").MarshalBinary()

	// no more metrics for conn1
	assert.EqualValues(t, map[connKey][]*model.HTTPTraceObservation{
		conn1Key: {
			{
				LatencySec:     0.8,
				TraceDirection: model.TraceDirection_request,
				TraceId:        []byte("traceId"),
				Method:         model.HTTPMethod_GET,
				Response:       200,
			},
			{
				LatencySec:     0.8,
				TraceDirection: model.TraceDirection_response,
				TraceId:        []byte("traceId"),
				Method:         model.HTTPMethod_POST,
				Response:       400,
			},
			{
				LatencySec:     0.8,
				TraceDirection: model.TraceDirection_request,
				TraceId:        v4trace,
				Method:         model.HTTPMethod_GET,
				Response:       200,
			},
		},
		conn2Key: {
			{
				LatencySec:     0.8,
				TraceDirection: model.TraceDirection_both,
				TraceId:        v1trace,
				Method:         model.HTTPMethod_GET,
				Response:       501,
			},
			{
				LatencySec:     0.45,
				TraceDirection: model.TraceDirection_response,
				TraceId:        v1trace,
				Method:         model.HTTPMethod_POST,
				Response:       200,
			},
		},
	}, observations)

}

func TestHTTPAggregation_SingleReq_NoPath(t *testing.T) {

	conn1req1 := http.NewKey(
		util.AddressFromString("10.0.0.1"), util.AddressFromString("192.168.1.1"), 12345, 80,
		[]byte("/page"), true, http.MethodGet, 0)

	conn1Key := getConnectionKeyForHTTPStats(conn1req1)

	conn1req1Stats := http.NewRequestStats(true)
	conn1req1Stats.AddRequest(200, msToNs(100), 0, nil)
	conn1req1Stats.AddRequest(400, msToNs(2), 0, nil)
	conn1req1Stats.AddRequest(400, msToNs(4), 0, nil)
	conn1req1Stats.AddRequest(400, msToNs(6), 0, nil)
	conn1req1Stats.AddRequest(400, msToNs(8), 0, nil)

	metrics := aggregateHTTPStats(map[http.Key]*http.RequestStats{
		conn1req1: conn1req1Stats,
	}, false)

	assert.Len(t, metrics, 1)
	conn1Metrics := metrics[conn1Key]
	assert.NotNil(t, conn1Metrics)

	sortConnectionMetrics(conn1Metrics)

	assertHTTPRequestsDeltaMetric(t, conn1Metrics[0], "1xx", "", "", 0)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[1], "2xx", "", "", 1)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[2], "3xx", "", "", 0)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[3], "4xx", "", "", 4)
	assertHTTPRequestsDeltaMetric(t, conn1Metrics[4], "5xx", "", "", 0)

	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[5], "1xx", "", "", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[6], "2xx", "", "", 100, 100, 1)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[7], "3xx", "", "", 0, 0, 0)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[8], "4xx", "", "", 2, 8, 4)
	assertHTTPResponseTimeConnectionMetric(t, conn1Metrics[9], "5xx", "", "", 0, 0, 0)

	assert.Len(t, conn1Metrics, 10)
}

func assertHTTPResponseTimeConnectionMetric(t *testing.T, formattedMetric *model.ConnectionMetric, statusCode, method, path string, minMs, maxMs, total int) {
	assert.Equal(t, "http_response_time_seconds", formattedMetric.Name)
	minSec := float64(minMs) / 1000.0
	maxSec := float64(maxMs) / 1000.0
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
		assert.Equal(t, total, int(math.Round(actualSketch.GetCount())), "Total doesn't match for status code `%s`", statusCode)
		var actualMin, actualMax float64
		if int(actualSketch.GetCount()) != 0 {
			actualMin, err = actualSketch.GetMinValue()
			assert.NoError(t, err)
			actualMax, err = actualSketch.GetMaxValue()
			assert.NoError(t, err)
		}
		if minSec == 0 {
			assert.Equal(t, 0.0, actualMin, "Min doesn't match for status code `%s`", statusCode)
		} else {
			// We use a 1% error margin to account for the fact that the sketch is not exact
			assert.InEpsilon(t, minSec, actualMin, 0.03, "Min doesn't match for status code `%s`", statusCode)
		}
		if maxSec == 0 {
			assert.Equal(t, 0.0, actualMax, "Max doesn't match for status code `%s`", statusCode)
		} else {
			// We use a 1% error margin to account for the fact that the sketch is not exact
			assert.InEpsilon(t, maxSec, actualMax, 0.03, "Max doesn't match for status code `%s`", statusCode)
		}
	}
}

func assertHTTPRequestsBaseMetric(t *testing.T, expectedMetric string, formattedMetric *model.ConnectionMetric, statusCode, method, path string, expectedValue float64) {
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

func assertHTTPRequestsDeltaMetric(t *testing.T, formattedMetric *model.ConnectionMetric, statusCode, method, path string, expectedDelta float64) {
	assertHTTPRequestsBaseMetric(t, "http_requests_delta", formattedMetric, statusCode, method, path, expectedDelta)
}
