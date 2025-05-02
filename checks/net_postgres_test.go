package checks

import (
	"math"
	"sort"
	"strings"
	"testing"

	"github.com/DataDog/datadog-agent/pkg/network/protocols/postgres"
	"github.com/DataDog/datadog-agent/pkg/network/types"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/sketches-go/ddsketch"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/stretchr/testify/assert"
)

func assertPostgresRequestsDelta(t *testing.T, formattedMetric *model.ConnectionMetric, DBname, TableName, SQLcommand string, expectedValue float64) {
	assert.Equal(t, string(postgresRequestsDelta), formattedMetric.Name)
	expectedTags := map[string]string{
		postgresDatabaseNameTag: DBname,
		postgresTableNameTag:    TableName,
		postgresSQLCommandTag:   SQLcommand,
	}
	assert.Equal(t, expectedTags, formattedMetric.Tags)
	assert.Equal(t, expectedValue, formattedMetric.Value.GetNumber())
}

func assertPostgresResponseTime(t *testing.T, formattedMetric *model.ConnectionMetric, DBname, TableName, SQLcommand string, samplesCount float64, expectedMaxNs, expectedMinNs float64) {
	assert.Equal(t, string(postgresResponseTime), formattedMetric.Name)
	expectedTags := map[string]string{
		postgresDatabaseNameTag: DBname,
		postgresTableNameTag:    TableName,
		postgresSQLCommandTag:   SQLcommand,
	}
	assert.Equal(t, expectedTags, formattedMetric.Tags)
	actualSketch, err := ddsketch.FromProto(formattedMetric.Value.GetHistogram())
	assert.NoError(t, err)
	assert.Equal(t, samplesCount, math.Round(actualSketch.GetCount()))
	actualMinS, err := actualSketch.GetMinValue()
	assert.NoError(t, err)
	actualMaxS, err := actualSketch.GetMaxValue()
	assert.NoError(t, err)
	// we could have an error of 3% on the min and max values
	assert.InEpsilon(t, expectedMaxNs*nsToS, actualMaxS, 0.03)
	assert.InEpsilon(t, expectedMinNs*nsToS, actualMinS, 0.03)
}

func sortPostgresMetrics(metrics []*model.ConnectionMetric) {
	sort.Slice(metrics, func(i, j int) bool {
		// Order by metric name
		if cmp := strings.Compare(metrics[i].Name, metrics[j].Name); cmp != 0 {
			return cmp < 0
		}
		// Order by Database Name
		if cmp := strings.Compare(metrics[i].Tags[postgresDatabaseNameTag], metrics[j].Tags[postgresDatabaseNameTag]); cmp != 0 {
			return cmp < 0
		}
		// Order by Table Name
		if cmp := strings.Compare(metrics[i].Tags[postgresTableNameTag], metrics[j].Tags[postgresTableNameTag]); cmp != 0 {
			return cmp < 0
		}
		// Order by SQL command
		if cmp := strings.Compare(metrics[i].Tags[postgresSQLCommandTag], metrics[j].Tags[postgresSQLCommandTag]); cmp != 0 {
			return cmp < 0
		}
		return false
	})
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

func TestPostgresAggregation(t *testing.T) {
	const (
		rootNS        = 0
		notRootNS     = 3
		table1        = "dummy_table"
		table2        = "dummy_table_2"
		database1     = "db1"
		emptyDatabase = ""
		maxLatNs      = 7980000430.0 // ~ 7.98 s
		minLatNs      = 32434430.3   // ~ 32.43 ms
	)

	// 3 different connections
	// Simple connection no root namespace
	conn := types.NewConnectionKey(util.AddressFromString("127.0.0.1"), util.AddressFromString("127.0.0.2"), 121, 80, rootNS)
	// Same but seen from not root namespace
	connSeenFromNs := types.NewConnectionKey(util.AddressFromString("127.0.0.1"), util.AddressFromString("127.0.0.2"), 121, 80, notRootNS)
	// Different tuple in the root namespace
	anotherConn := types.NewConnectionKey(util.AddressFromString("10.0.0.1"), util.AddressFromString("10.0.0.3"), 34, 96, rootNS)

	stat := map[postgres.Key]*postgres.RequestStat{
		postgres.NewKeyFromConnection(&conn, postgres.CreateTableOP, table1, database1):      {},
		postgres.NewKeyFromConnection(&conn, postgres.SelectOP, table1, database1):           {},
		postgres.NewKeyFromConnection(&conn, postgres.InsertOP, table2, emptyDatabase):       {},
		postgres.NewKeyFromConnection(&connSeenFromNs, postgres.SelectOP, table2, database1): {},
		postgres.NewKeyFromConnection(&anotherConn, postgres.UpdateOP, table2, database1):    {},
	}

	for k, v := range stat {
		v.StaticTags = 0
		v.Count = 2
		v.FirstLatencySample = maxLatNs
		v.Latencies = emptySketch()
		v.Latencies.Add(v.FirstLatencySample)
		v.Latencies.Add(minLatNs)
		// If the operation is SELECT, we add the latency to the sketch
		if k.Operation == postgres.SelectOP {
			v.Latencies.Add(minLatNs)
			v.Count++
		}
	}

	connMap := aggregatePostgresStats(stat)
	assert.Len(t, connMap, 3)

	for k, metrics := range connMap {
		if compareWithDataDogDual(&k, &conn) {
			// we expect 6 metrics
			assert.Len(t, metrics, 6)
			sortPostgresMetrics(metrics)
			assertPostgresRequestsDelta(t, metrics[0], emptyDatabase, table2, postgres.InsertOP.String(), 2)
			assertPostgresRequestsDelta(t, metrics[1], database1, table1, postgres.CreateTableOP.String(), 2)
			assertPostgresRequestsDelta(t, metrics[2], database1, table1, postgres.SelectOP.String(), 3)
			assertPostgresResponseTime(t, metrics[3], emptyDatabase, table2, postgres.InsertOP.String(), 2, maxLatNs, minLatNs)
			assertPostgresResponseTime(t, metrics[4], database1, table1, postgres.CreateTableOP.String(), 2, maxLatNs, minLatNs)
			assertPostgresResponseTime(t, metrics[5], database1, table1, postgres.SelectOP.String(), 3, maxLatNs, minLatNs)
		} else if compareWithDataDogDual(&k, &connSeenFromNs) {
			// we expect 2 metrics
			assert.Len(t, metrics, 2)
			sortPostgresMetrics(metrics)
			assertPostgresRequestsDelta(t, metrics[0], database1, table2, postgres.SelectOP.String(), 3)
			assertPostgresResponseTime(t, metrics[1], database1, table2, postgres.SelectOP.String(), 3, maxLatNs, minLatNs)
		} else if compareWithDataDogDual(&k, &anotherConn) {
			// we expect 2 metrics
			assert.Len(t, metrics, 2)
			sortPostgresMetrics(metrics)
			assertPostgresRequestsDelta(t, metrics[0], database1, table2, postgres.UpdateOP.String(), 2)
			assertPostgresResponseTime(t, metrics[1], database1, table2, postgres.UpdateOP.String(), 2, maxLatNs, minLatNs)
		}
	}

}
