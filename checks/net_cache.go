package checks

import (
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"github.com/patrickmn/go-cache"
	"time"
)

// RelationCache is used as the struct in the cache for all seen processes
type RelationCache struct {
	ConnectionStats common.ConnectionStats
	FirstObserved   int64
	LastObserved    int64
}

func isRelationCached(c *cache.Cache, relationID string) (*RelationCache, bool) {
	cPointer, found := c.Get(relationID)
	if found {
		return cPointer.(*RelationCache), true
	}

	return nil, false
}

func putRelationCache(c *cache.Cache, relationID string, connStats common.ConnectionStats) *RelationCache {
	var cachedRelation *RelationCache
	nowUnix := time.Now().Unix()

	cPointer, found := c.Get(relationID)
	if found {
		cachedRelation = cPointer.(*RelationCache)
		cachedRelation.ConnectionStats = connStats
		cachedRelation.LastObserved = nowUnix
	} else {
		cachedRelation = &RelationCache{
			ConnectionStats: connStats,
			FirstObserved:   nowUnix,
			LastObserved:    nowUnix,
		}
	}

	c.Set(relationID, cachedRelation, cache.DefaultExpiration)
	return cachedRelation
}
