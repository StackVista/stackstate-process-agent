package pods

import (
	"context"
	"github.com/StackVista/stackstate-agent/pkg/util/kubernetes/kubelet"
	log "github.com/cihub/seelog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"time"
)

type Watcher struct {
	kubeutil       kubelet.KubeUtilInterface
	updateInterval time.Duration
	expirationTime time.Duration
	stopCh         chan interface{}

	containerIDToPod map[string]*podEntry
	podsGauge        prometheus.Gauge
}

type podEntry struct {
	pod      *kubelet.Pod
	lastSeen time.Time
}

func MakeWatcher(updateInterval time.Duration, expirationTime time.Duration) (*Watcher, error) {
	kubeutil, retrier := kubelet.GetKubeUtilWithRetrier()
	if kubeutil == nil {
		return nil, retrier.LastError()
	}
	return &Watcher{
		kubeutil:       kubeutil,
		updateInterval: updateInterval,
		expirationTime: expirationTime,
		podsGauge: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: "stackstate_process_agent",
			Subsystem: "pods_watcher",
			Name:      "pods",
			Help:      "Number of pods in state",
		}),
		containerIDToPod: make(map[string]*podEntry),
	}, nil
}

func (p *Watcher) Start(ctx context.Context) {
	go func() {
		// Initial update
		p.updatePods(ctx)

		// Start update loop
		updateTicker := time.NewTicker(p.updateInterval)
		for {
			select {
			case <-updateTicker.C:
				p.updatePods(ctx)
			case <-p.stopCh:
				updateTicker.Stop()
				return
			}
		}
	}()
}

func (p *Watcher) Stop() {
	p.stopCh <- nil
	close(p.stopCh)
}

func (p *Watcher) GetPodForContainerID(containerID string) *kubelet.Pod {
	if entry, ok := p.containerIDToPod[containerID]; ok {
		return entry.pod
	}
	return nil
}

func (p *Watcher) updatePods(ctx context.Context) {
	// get new pods
	pods, err := p.kubeutil.GetLocalPodList(ctx)
	log.Debugf("GetLocalPodList result: %v, %v", len(pods), err)
	if err != nil {
		_ = log.Errorf("Could not get pods: %s", err)
		return
	}
	now := time.Now()
	for _, pod := range pods {
		log.Tracef("Got pod: %v", pod)
		for _, container := range pod.Status.Containers {
			p.containerIDToPod[kubelet.TrimRuntimeFromCID(container.ID)] = &podEntry{
				pod:      pod,
				lastSeen: now,
			}
		}
	}

	// cleanup old pods
	for containerID, entry := range p.containerIDToPod {
		if now.Sub(entry.lastSeen) > p.expirationTime {
			delete(p.containerIDToPod, containerID)
		}
	}

	p.podsGauge.Set(float64(len(p.containerIDToPod)))
}
