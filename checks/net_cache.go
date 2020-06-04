package checks

import (
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"github.com/patrickmn/go-cache"
	"time"
)

// RelationCache is used as the struct in the cache for all seen processes
type RelationCache struct {
	Connection       *model.EnrichedConnection
	LastSentBytes uint64
	LastReceivedBytes uint64
	FirstObserved int64
	LastObserved  int64
}

func isRelationCached(c *cache.Cache, connStats common.ConnectionStats) (*RelationCache, bool) {
	//TODO: convert common.ConnectionStats to *model.EnrichedConnection
	var conn *model.EnrichedConnection
	relationID := createRelationIdentifier(conn)

	cPointer, found := c.Get(relationID)
	if found {
		return cPointer.(*RelationCache), true
	}

	return nil, false
}

func putRelationCache(c *cache.Cache, connStats common.ConnectionStats) *RelationCache {
	//TODO: convert common.ConnectionStats to *model.EnrichedConnection
	var conn *model.EnrichedConnection

	var cachedRelation *RelationCache
	relationID := createRelationIdentifier(conn)
	nowUnix := time.Now().Unix()

	cPointer, found := c.Get(relationID)
	if found {
		cachedRelation = cPointer.(*RelationCache)
		cachedRelation.Connection = conn
		cachedRelation.LastObserved = nowUnix
	} else {
		cachedRelation = &RelationCache{
			Connection:       conn,
			FirstObserved: nowUnix,
			LastObserved:  nowUnix,
		}
	}

	c.Set(relationID, cachedRelation, cache.DefaultExpiration)
	return cachedRelation
}

