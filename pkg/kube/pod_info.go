package kube

import (
	"fmt"
	"regexp"
	"sort"
	"time"
)

var nonAlphanumericRegex = regexp.MustCompile(`[^a-zA-Z0-9]`)

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

func convertLabelsKeyIntoOtelFormat(labels map[string]string) map[string]string {
	newLabels := make(map[string]string, len(labels))
	for oldKey, v := range labels {
		// We want to replace all non-alphanumeric characters with "."
		newLabels[nonAlphanumericRegex.ReplaceAllString(oldKey, ".")] = v
	}
	return newLabels
}

// PodInfo holds the metadata of a pod.
type PodInfo struct {
	Name              string
	Namespace         string
	Labels            map[string]string
	CreationTimestamp int64
	DeletionTimestamp int64
}
