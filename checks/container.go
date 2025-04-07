//go:build linux
// +build linux

package checks

import (
	"fmt"
	"strings"
	"time"

	ddmodel "github.com/DataDog/agent-payload/v5/process"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/model/telemetry"
)

func retrieveMetricsAndFormat(cfg *config.AgentConfig, ctrList []*ddmodel.Container) ([]*model.Container, []telemetry.RawMetric) {
	multiMetrics := make([]telemetry.RawMetric, 0)
	containers := make([]*model.Container, 0)

	for _, c := range ctrList {
		container, mm := fmtContainer(cfg, c)
		multiMetrics = append(multiMetrics, mm...)
		containers = append(containers, container)
	}

	return containers, multiMetrics
}

// fmtContainers formats a container given raw data to the output values
func fmtContainer(
	cfg *config.AgentConfig,
	ctr *ddmodel.Container,
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
