package pods

import (
	"context"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/kubelet"
	"github.com/DataDog/datadog-agent/pkg/util/retry"
	log "github.com/cihub/seelog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"time"
)

// CachedPods is a proxy to kubelet util that keeps a pod for some time (expirationTime) after it disappear from kubelet result
type CachedPods struct {
	expirationTime   time.Duration
	containerIDToPod map[string]*podEntry
	getKubeutil      func() (kubelet.KubeUtilInterface, *retry.Retrier)
}

type podEntry struct {
	pod      *kubelet.Pod
	lastSeen time.Time
}

var podsInKubeletGauge = promauto.NewGauge(prometheus.GaugeOpts{
	Namespace: "stackstate_process_agent",
	Subsystem: "pods",
	Name:      "kubelet",
	Help:      "Number of pods received from the kubelet",
})

var podsInCacheGauge = promauto.NewGauge(prometheus.GaugeOpts{
	Namespace: "stackstate_process_agent",
	Subsystem: "pods",
	Name:      "cached",
	Help:      "Number of pods in the cache",
})

// MakeCachedPods returns a new CachedPods
func MakeCachedPods(expirationTime time.Duration) *CachedPods {
	return &CachedPods{
		expirationTime:   expirationTime,
		containerIDToPod: make(map[string]*podEntry),
		getKubeutil:      kubelet.GetKubeUtilWithRetrier,
	}
}

// GetContainerToPodMap returns a map from containerID to its pod
func (p *CachedPods) GetContainerToPodMap(ctx context.Context) map[string]*kubelet.Pod {
	result := make(map[string]*kubelet.Pod)

	kubeutil, retrier := p.getKubeutil()
	if kubeutil == nil {
		_ = log.Errorf("Could not get kubeutil: %v", retrier.LastError())
		return result
	}

	// get new pods
	pods, err := kubeutil.GetLocalPodList(ctx)
	if err != nil {
		_ = log.Errorf("Could not get pods: %s", err)
		return result
	}
	podsInKubeletGauge.Set(float64(len(pods)))

	now := time.Now()
	// add new pods to the state
	for _, pod := range pods {
		for _, container := range pod.Status.Containers {
			trimmedID := kubelet.TrimRuntimeFromCID(container.ID)
			if trimmedID != "" {
				p.containerIDToPod[trimmedID] = &podEntry{
					pod:      pod,
					lastSeen: now,
				}
			}
		}
	}
	// build result (without expiration time) and cleanup old pods
	for containerID, entry := range p.containerIDToPod {
		if now.Sub(entry.lastSeen) <= p.expirationTime {
			result[containerID] = entry.pod
		} else {
			delete(p.containerIDToPod, containerID)
		}
	}
	podsInCacheGauge.Set(float64(len(p.containerIDToPod)))

	return result
}
