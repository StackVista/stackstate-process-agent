//go:build linux
// +build linux

package checks

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/util/containers/metrics/provider"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/model/telemetry"
	"strings"
	"time"

	log "github.com/cihub/seelog"

	ddmodel "github.com/DataDog/agent-payload/v5/process"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
)

func retrieveMetricsAndFormat(cfg *config.AgentConfig, ctrList []*ddmodel.Container) ([]*model.Container, []telemetry.RawMetric) {
	multiMetrics := make([]telemetry.RawMetric, 0)
	containers := make([]*model.Container, 0)

	for _, c := range ctrList {
		stats := retrieveAdditionalStats(c)
		container, mm := fmtContainer(cfg, c, stats)
		multiMetrics = append(multiMetrics, mm...)
		containers = append(containers, container)
	}

	return containers, multiMetrics
}

// retrieveAdditionalStats gets data on top of the already retrieved data for containers.
func retrieveAdditionalStats(c *ddmodel.Container) *provider.ContainerStats {
	// This function is programmed defensively, due to this code being executed outside of the main collection run,
	// so containers/ids/providers might have changed since collection (hard to prove ootherwise given the global nature of
	// the data in the datadog dependency).

	// Retrieve the container metadata, to get hold of the namespace
	containerMeta, err := workloadmeta.GetGlobalStore().GetContainer(c.Id)

	if err != nil {
		// Question: are there benefits to making the collector not global?
		collector := provider.GetProvider().GetCollector(string(fromTypeToContainerRuntime(c.Type)))
		stats, err := collector.GetContainerStats(containerMeta.Namespace, c.Id, 2*time.Second)
		if err != nil {
			return stats
		}

		log.Warnf("Could not get container stats for container: %s", c.Id)
	} else {
		log.Warnf("Could not get container metaData for container: %s", c.Id)
	}

	return nil
}

// fromTypeToContainerRuntime is essentially the inverse of datad agents' process/util/containgers.go:260 convertContainerRuntime
func fromTypeToContainerRuntime(runtime string) workloadmeta.ContainerRuntime {
	// ECSFargate is special and used to be mapped to "ECS"
	if runtime == "ECS" {
		return workloadmeta.ContainerRuntimeECSFargate
	}

	return workloadmeta.ContainerRuntime(runtime)
}

// fmtContainers formats a container given raw data to the output values
func fmtContainer(
	cfg *config.AgentConfig,
	ctr *ddmodel.Container,
	stats *provider.ContainerStats,
) (*model.Container, []telemetry.RawMetric) {

	multiMetrics := make([]telemetry.RawMetric, 0)

	container := &model.Container{
		Id:          ctr.Id,
		Type:        ctr.Type,
		CpuLimit:    float32(ctr.CpuLimit),
		MemoryLimit: ctr.MemoryLimit,
		Created:     ctr.Created,
		State:       model.ContainerState(model.ContainerState_value[ctr.State.String()]),
		Health:      model.ContainerHealth(model.ContainerHealth_value[ctr.Health.String()]),
		Started:     ctr.Started,
		Tags:        transformKubernetesTags(ctr.Tags, cfg.ClusterName),
	}

	metricTags := []string{fmt.Sprintf("containerId:%s", ctr.Id)}
	timestamp := time.Now().Unix()
	makeMetric := func(name string, value float64) telemetry.RawMetric {
		return telemetry.RawMetric{
			Name: name, Timestamp: timestamp, HostName: cfg.HostName, Value: value, Tags: metricTags,
		}
	}

	appendIfDefined := func(metrics []telemetry.RawMetric, name string, value *float64) []telemetry.RawMetric {
		if value == nil {
			return metrics
		}

		return append(metrics, makeMetric(name, *value))
	}

	if stats != nil {
		if stats.CPU != nil {
			multiMetrics = appendIfDefined(multiMetrics, "container_cpu_throttled_time_total", stats.CPU.ThrottledTime)
			multiMetrics = appendIfDefined(multiMetrics, "container_cpu_throttled_periods_total", stats.CPU.ThrottledPeriods)
		}

		if stats.PID != nil {
			multiMetrics = appendIfDefined(multiMetrics, "cpuThreadCount", stats.PID.ThreadCount)
		}
	}

	multiMetrics = append(multiMetrics,
		makeMetric("rbps", float64(ctr.Rbps)),
		makeMetric("wbps", float64(ctr.Wbps)),
		makeMetric("netRcvdPs", float64(ctr.NetRcvdPs)),
		makeMetric("netSentPs", float64(ctr.NetSentPs)),
		makeMetric("netRcvdBps", float64(ctr.NetRcvdBps)),
		makeMetric("netSentBps", float64(ctr.NetSentBps)),
		makeMetric("userPct", float64(ctr.UserPct)),
		makeMetric("systemPct", float64(ctr.SystemPct)),
		makeMetric("totalPct", float64(ctr.TotalPct)),
		makeMetric("memRss", float64(ctr.MemRss)),
		makeMetric("memCache", float64(ctr.MemCache)),
	)

	return container, multiMetrics
}

func transformKubernetesTags(tags []string, clusterName string) []string {
	updatedTags := make([]string, 0, len(tags))

	for _, tag := range tags {
		if strings.HasPrefix(tag, "pod_name:") {
			podName := strings.Split(tag, "pod_name:")[1]
			updatedTags = append(updatedTags, fmt.Sprintf("pod-name:%s", podName))
		} else if strings.HasPrefix(tag, "kube_namespace:") {
			namespace := strings.Split(tag, "kube_namespace:")[1]
			updatedTags = append(updatedTags, fmt.Sprintf("namespace:%s", namespace))
		} else {
			updatedTags = append(updatedTags, tag)
		}
	}

	if clusterName != "" {
		updatedTags = append(updatedTags, fmt.Sprintf("cluster-name:%s", clusterName))
	}

	return updatedTags
}
