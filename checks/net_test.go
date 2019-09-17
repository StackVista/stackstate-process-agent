package checks

import (
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"os"
	"testing"
	"time"

	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/stretchr/testify/assert"
)

func makeConnection(pid int32) *model.Connection {
	return &model.Connection{Pid: pid}
}

func TestNetworkConnectionMax(t *testing.T) {
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
			expectedTotal:  1,
			expectedChunks: 1,
		},
		{
			cur:            []*model.Connection{p[0], p[1], p[2]},
			maxSize:        2,
			expectedTotal:  2,
			expectedChunks: 1,
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
			expectedTotal:  3,
			expectedChunks: 1,
		},
		{
			cur:            []*model.Connection{p[0], p[1], p[2], p[3], p[2], p[3]},
			maxSize:        2,
			expectedTotal:  2,
			expectedChunks: 1,
		},
	} {
		cfg.MaxPerMessage = tc.maxSize
		chunks := batchConnections(cfg, 0, tc.cur)

		assert.Len(t, chunks, tc.expectedChunks, "len %d", i)
		total := 0
		for _, c := range chunks {
			connections := c.(*model.CollectorConnections)
			total += len(connections.Connections)
			assert.Equal(t, int32(tc.expectedChunks), connections.GroupSize, "group size test %d", i)
		}
		assert.Equal(t, tc.expectedTotal, total, "total test %d", i)
	}
}

func makeConnectionStats(pid uint32) common.ConnectionStats {
	return common.ConnectionStats{Pid: pid}
}

func TestNetworkConnectionNamespaceKubernetes(t *testing.T) {
	p := []common.ConnectionStats{
		makeConnectionStats(1),
		makeConnectionStats(2),
		makeConnectionStats(3),
		makeConnectionStats(4),
	}

	testClusterName := "test-cluster"
	_ = os.Setenv("CLUSTER_NAME", testClusterName)

	now := time.Now()

	connections := Connections.formatConnections(p, make(map[string]common.ConnectionStats, 0), now.Add(-10*time.Second))

	assert.Len(t, connections, 4)
	for _, c := range connections {
		assert.Contains(t, c.Namespace, testClusterName)
	}
}