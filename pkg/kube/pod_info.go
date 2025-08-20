package kube

import (
	"fmt"
	"sort"
)

func (p *PodInfo) String() string {
	return fmt.Sprintf("%s/%s", p.Namespace, p.Name)
}

func stringifyPodLabels(labels map[string]string) string {
	labelsStr := make([]string, 0, len(labels))
	for k, v := range labels {
		labelsStr = append(labelsStr, fmt.Sprintf("%s=%s", k, v))
	}
	// we need them in order otherwise OTEL will not be able to aggregate them correctly
	sort.Strings(labelsStr)
	return fmt.Sprintf("%v", labelsStr)
}

// PodInfo holds the metadata of a pod.
type PodInfo struct {
	Name              string
	Namespace         string
	Labels            string
	CreationTimestamp int64
	DeletionTimestamp int64
}
