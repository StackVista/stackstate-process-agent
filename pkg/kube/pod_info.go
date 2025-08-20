package kube

import "fmt"

func (p *PodInfo) String() string {
	return fmt.Sprintf("%s/%s", p.Namespace, p.Name)
}

func (p *PodInfo) LabelsString() string {
	var labels []string
	for k, v := range p.Labels {
		labels = append(labels, fmt.Sprintf("%s=%s", k, v))
	}
	return fmt.Sprintf("%v", labels)
}

// PodInfo holds the metadata of a pod.
type PodInfo struct {
	Name              string
	Namespace         string
	Labels            map[string]string
	CreationTimestamp int64
	DeletionTimestamp int64
}
