package kube

import "fmt"

func (p *PodInfo) String() string {
	return fmt.Sprintf("%s/%s", p.Namespace, p.Name)
}

// PodInfo holds the metadata of a pod.
type PodInfo struct {
	Name              string
	Namespace         string
	Labels            map[string]string
	CreationTimestamp int64
	DeletionTimestamp int64
}
