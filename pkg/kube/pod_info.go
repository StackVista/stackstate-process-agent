package kube

import (
	"fmt"
	"sort"
	"time"
)

func (p *PodInfo) String() string {
	deletionTs := time.Unix(p.DeletionTimestamp, 0).String()
	if p.DeletionTimestamp == 0 {
		deletionTs = "ALIVE" // zero value for deletion timestamp
	}
	return fmt.Sprintf("%s/%s [%v -> %v]", p.Namespace, p.Name, time.Unix(p.CreationTimestamp, 0), deletionTs)
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
