package pods

import (
	"context"
	"github.com/StackVista/stackstate-agent/pkg/util/kubernetes/kubelet"
	log "github.com/cihub/seelog"
	"time"
)

type Watcher struct {
	kubeutil       kubelet.KubeUtilInterface
	updateInterval time.Duration
	expirationTime time.Duration
	stopCh         chan interface{}

	ipToPod          map[string]*podEntry
	containerIDToPod map[string]*podEntry
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
	if err != nil {
		_ = log.Errorf("Could not get pods: %s", err)
		return
	}
	now := time.Now()
	for _, pod := range pods {
		if pod.Status.PodIP != pod.Status.HostIP {
			p.ipToPod[pod.Status.PodIP] = &podEntry{
				pod:      pod,
				lastSeen: now,
			}
		}
		for _, container := range pod.Status.Containers {
			p.containerIDToPod[container.ID] = &podEntry{
				pod:      pod,
				lastSeen: now,
			}
		}
	}

	// cleanup old pods
	for ip, entry := range p.ipToPod {
		if now.Sub(entry.lastSeen) > p.expirationTime {
			delete(p.ipToPod, ip)
		}
	}
	for containerID, entry := range p.containerIDToPod {
		if now.Sub(entry.lastSeen) > p.expirationTime {
			delete(p.containerIDToPod, containerID)
		}
	}
}
