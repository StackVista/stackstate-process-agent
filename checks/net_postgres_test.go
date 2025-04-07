package checks

import (
	"math"
	"testing"

	"github.com/DataDog/datadog-agent/pkg/network/protocols/postgres"
	"github.com/DataDog/datadog-agent/pkg/network/types"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/sketches-go/ddsketch"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/stretchr/testify/assert"
)

const (
	rootNS    = 0
	notRootNS = 3
)

// Move this to Datadog Postgres
func createPostgresKeyFromConn(c *types.ConnectionKey, operation postgres.Operation, parameters string) postgres.Key {
	return postgres.Key{
		ConnectionKey: *c,
		Operation:     operation,
		Parameters:    parameters,
	}
}

func assertPostgresRequestsDelta(t *testing.T, formattedMetric *model.ConnectionMetric, expectedValue float64) {
	assert.Equal(t, string(postgresRequestsDelta), formattedMetric.Name)
	assert.Equal(t, map[string]string{}, formattedMetric.Tags)
	// formattedMetric.Value.GetNumber() could be for example `1.999999999999993` instead of `2`.
	// todo!: Do we round it in the platform?
	assert.Equal(t, expectedValue, math.Round(formattedMetric.Value.GetNumber()))
}

func assertPostgresResponseTime(t *testing.T, formattedMetric *model.ConnectionMetric, samplesCount int, expectedMaxNs, expectedMinNs float64) {
	assert.Equal(t, string(postgresResponseTime), formattedMetric.Name)
	assert.Equal(t, map[string]string{}, formattedMetric.Tags)
	actualSketch, err := ddsketch.FromProto(formattedMetric.Value.GetHistogram())
	assert.NoError(t, err)
	assert.Equal(t, samplesCount, int(math.Round(actualSketch.GetCount())))
	actualMinS, err := actualSketch.GetMinValue()
	assert.NoError(t, err)
	actualMaxS, err := actualSketch.GetMaxValue()
	assert.NoError(t, err)
	// we could have an error of 3% on the min and max values
	assert.InEpsilon(t, expectedMaxNs*nsToS, actualMaxS, 0.03)
	assert.InEpsilon(t, expectedMinNs*nsToS, actualMinS, 0.03)
}

// todo!: we can remove this if we adopt the datadog connection model.
func compareWithDataDogDual(c *connKey, ddc *types.ConnectionKey) bool {
	return c.SrcIPHigh == ddc.SrcIPHigh &&
		c.SrcIPLow == ddc.SrcIPLow &&
		c.SrcPort == ddc.SrcPort &&
		c.DstIPHigh == ddc.DstIPHigh &&
		c.DstIPLow == ddc.DstIPLow &&
		c.DstPort == ddc.DstPort &&
		c.NetNs == ddc.NetNs
}

func isPostgresRequestsDeltaMetric(formattedMetric *model.ConnectionMetric) bool {
	return formattedMetric.Name == string(postgresRequestsDelta)
}

func TestPostgresAggregation(t *testing.T) {
	// Simple connection no root namespace
	conn := types.NewConnectionKey(util.AddressFromString("127.0.0.1"), util.AddressFromString("127.0.0.2"), 121, 80, rootNS)
	// Same but seen from not root namespace
	connSeenFromNs := types.NewConnectionKey(util.AddressFromString("127.0.0.1"), util.AddressFromString("127.0.0.2"), 121, 80, notRootNS)
	// Different tuple in the root namespace
	anotherConn := types.NewConnectionKey(util.AddressFromString("10.0.0.1"), util.AddressFromString("10.0.0.3"), 34, 96, rootNS)

	// todo!: rework this when we will support the metrics tags
	stat := map[postgres.Key]*postgres.RequestStat{
		/////////////////// We aggregate these together
		createPostgresKeyFromConn(&conn, postgres.SelectOP, "dummy_table"): {},
		// Different operation
		createPostgresKeyFromConn(&conn, postgres.InsertOP, "dummy_table"): {},
		// Different table
		createPostgresKeyFromConn(&conn, postgres.SelectOP, "dummy_table_2"): {},
		///////////////////
		createPostgresKeyFromConn(&connSeenFromNs, postgres.SelectOP, "dummy_table"): {},
		///////////////////
		createPostgresKeyFromConn(&anotherConn, postgres.SelectOP, "dummy_table"): {},
	}

	maxLatNs := 7980000430.0 // ~ 7.98 s
	minLatNs := 32434430.3   // ~ 32.43 ms

	// we initialize the stats for each key
	for _, v := range stat {
		v.StaticTags = 0
		v.Count = 2
		v.FirstLatencySample = maxLatNs
		v.Latencies = emptySketch()
		v.Latencies.Add(v.FirstLatencySample)
		v.Latencies.Add(minLatNs)
	}

	connMap := aggregatePostgresStats(stat)
	assert.Len(t, connMap, 3)

	for k, metrics := range connMap {
		if compareWithDataDogDual(&k, &conn) {
			// we expect 6 metrics
			assert.Len(t, metrics, 6)
			for _, m := range metrics {
				if isPostgresRequestsDeltaMetric(m) {
					assertPostgresRequestsDelta(t, m, 2)
				} else {
					assertPostgresResponseTime(t, m, 2, maxLatNs, minLatNs)
				}
			}
		} else if compareWithDataDogDual(&k, &connSeenFromNs) {
			// we expect 2 metrics
			assert.Len(t, metrics, 2)
			for _, m := range metrics {
				if isPostgresRequestsDeltaMetric(m) {
					assertPostgresRequestsDelta(t, m, 2)
				} else {
					assertPostgresResponseTime(t, m, 2, maxLatNs, minLatNs)
				}
			}
		} else if compareWithDataDogDual(&k, &anotherConn) {
			// we expect 2 metrics
			assert.Len(t, metrics, 2)
			for _, m := range metrics {
				if isPostgresRequestsDeltaMetric(m) {
					assertPostgresRequestsDelta(t, m, 2)
				} else {
					assertPostgresResponseTime(t, m, 2, maxLatNs, minLatNs)
				}
			}
		}
	}

}
