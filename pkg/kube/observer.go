package kube

import (
	"fmt"
	"time"

	"github.com/DataDog/datadog-agent/pkg/process/util"
	log "github.com/cihub/seelog"
	"github.com/shirou/gopsutil/v4/host"

	"sync"

	"go.opentelemetry.io/obi/pkg/kubecache/informer"
)

// PodInfo holds the metadata of a pod.
type PodInfo struct {
	Name              string
	Namespace         string
	Labels            map[string]string
	DeletionTimestamp uint64
}

// Observer implements the informer.Observer interface to observe Kubernetes events.
type Observer struct {
	// when we receive an event from the informer, we write the cache
	// when we want to read from the cache, we need to acquire a read lock
	access sync.RWMutex
	// the cache probably should be just name, namespace and labels
	activePodByIP  map[util.Address]*PodInfo
	deletedPodByIP map[util.Address]*PodInfo
	// Each `refreshDeletedPodInterval` minutes we will remove the deleted pods from the cache
	refreshDeletedPodInterval time.Duration
	// Last time we refreshed the deleted pods cache
	lastrefreshDeletedPod time.Time
	bootTime              uint64
}

// NewObserver creates a new Observer instance.
func NewObserver(refreshDeletedPodInterval time.Duration) (*Observer, error) {
	// we need the boot time because all what we receive from ebpf is the time in nanoseconds since boot
	bt, err := host.BootTime()
	if err != nil {
		return nil, fmt.Errorf("failed to get boot time: %w", err)
	}

	return &Observer{
		activePodByIP:             make(map[util.Address]*PodInfo),
		deletedPodByIP:            make(map[util.Address]*PodInfo),
		refreshDeletedPodInterval: refreshDeletedPodInterval,
		lastrefreshDeletedPod:     time.Now(),
		bootTime:                  bt,
	}, nil
}

// ID implements the Observer interface for Observer
func (o *Observer) ID() string { return "unique-metadata-observer" }

// On implements the Observer interface for Observer
func (o *Observer) On(event *informer.Event) error {
	// we are only interested in Pod events
	if event.Resource == nil || event.Resource.Kind != "Pod" {
		return nil
	}

	switch event.Type {
	// the informer sends all the pods that were already running with a create event. This create event already contains the IPs.
	// All the following create events will not contain the IPs
	case informer.EventType_UPDATED, informer.EventType_CREATED:
		o.upsertPodMeta(event.Resource)

	case informer.EventType_DELETED:
		o.deletePodMeta(event.Resource)

	// At the moment we don't need this one. Used only by the original OBI implementation
	// case informer.EventType_SYNC_FINISHED

	default:
	}
	return nil
}

func (o *Observer) upsertPodMeta(meta *informer.ObjectMeta) {
	o.access.Lock()
	defer o.access.Unlock()

	// This is possible in at least two cases:
	// 1. We receive a pod creation event for a new pod.
	// 2. The pod is running in the hostNetwork. The acutal informer implementation does not send the IPs for hostNetwork pods.
	//    but for us this is not an issue because the ip would be the Ip of the node so we don't need it.
	if len(meta.Ips) == 0 {
		return
	}

	// We need an array because a pod can have more than one IP, ipv6/ipv4, we use a separate entry for each IP.
	// We should update only if the labels are different, but for now we just overwrite every time.
	for _, ip := range meta.Ips {
		addr := util.AddressFromString(ip)
		if !addr.IsValid() {
			log.Warnf("invalid IP address %s for pod %s/%s", ip, meta.Namespace, meta.Name)
			continue
		}

		log.Debugf("upsert pod to store: %s/%s with IP %v and labels %v",
			meta.Namespace, meta.Name, ip, meta.Labels)

		o.activePodByIP[addr] = &PodInfo{
			Name:      meta.Name,
			Namespace: meta.Namespace,
			Labels:    meta.Labels,
		}
	}
}

func (o *Observer) deletePodMeta(meta *informer.ObjectMeta) {
	o.access.Lock()
	defer o.access.Unlock()

	// if the time is elapsed we need to remove the deleted cache
	// we can also use a dedicate goroutine with a ticker to do this, but this is simpler for now
	if o.lastrefreshDeletedPod.Add(o.refreshDeletedPodInterval).After(time.Now()) {
		o.deletedPodByIP = make(map[util.Address]*PodInfo)
		o.lastrefreshDeletedPod = time.Now()
	}

	for _, ip := range meta.Ips {
		addr := util.AddressFromString(ip)
		if !addr.IsValid() {
			log.Warnf("invalid IP address %s for pod %s/%s", ip, meta.Namespace, meta.Name)
			continue
		}
		// if the pod is not in the active cache, we can just add it to the deleted cache
		podInfo, ok := o.activePodByIP[addr]
		if !ok {
			o.deletedPodByIP[addr] = &PodInfo{
				Name:              meta.Name,
				Namespace:         meta.Namespace,
				Labels:            meta.Labels,
				DeletionTimestamp: uint64(meta.StatusTimeEpoch),
			}
		} else {
			podInfo.DeletionTimestamp = uint64(meta.StatusTimeEpoch)
			o.deletedPodByIP[addr] = podInfo
			delete(o.activePodByIP, addr)
		}
	}

	log.Debugf("removing pod from store: %s/%s with IPs %v",
		meta.Namespace, meta.Name, meta.Ips)
}

// ResolvePodsByIPs resolves the pods by their IPs, returning the PodInfo for each IP.
func (o *Observer) ResolvePodsByIPs(srcIP, dstIP util.Address, duration time.Duration, closed bool) (srcPod *PodInfo, dstPod *PodInfo) {
	o.access.RLock()
	defer o.access.RUnlock()
	srcPod = o.resolvePodByIPNoLock(srcIP, duration, closed)
	dstPod = o.resolvePodByIPNoLock(dstIP, duration, closed)
	return
}

// ResolvePodByIP resolves a pod by its IP, returning the PodInfo for the IP.
func (o *Observer) ResolvePodByIP(ip util.Address, duration time.Duration, closed bool) *PodInfo {
	o.access.RLock()
	defer o.access.RUnlock()
	return o.resolvePodByIPNoLock(ip, duration, closed)
}

func (o *Observer) resolvePodByIPNoLock(ip util.Address, duration time.Duration, closed bool) *PodInfo {
	oldPodInfo := o.deletedPodByIP[ip]
	newPodInfo := o.activePodByIP[ip]

	if oldPodInfo == nil {
		// newPodInfo could be nil, if the pod is not in the cache
		return newPodInfo
	}

	// If we arrive here it means that the pod was deleted
	if closed {
		// this is an approximation we should have at least the creation time of the connection but we don't have it
		// when the connection is closed the duration is no more the startup time but is the connection duration
		// the duration is in nanoseconds, so we need to convert it to seconds
		if uint64(time.Now().Unix())-oldPodInfo.DeletionTimestamp > uint64(duration.Seconds()) {
			// here we are not sure the connection belongs to the new pod everything is more a guess.
			return newPodInfo
		}
		// the duration of the connection is greater than the diff between the current time and the deletion timestamp
		return oldPodInfo
	}

	// If the connection is not closed, the duration is the creation time of the connection in nanoseconds starting from boot
	// so we need to sum the boot time to the duration to get the actual creation time of the connection
	creationTime := o.bootTime + uint64(duration.Seconds())
	if creationTime > uint64(oldPodInfo.DeletionTimestamp) {
		// the connection is newer than the old pod, so it belongs to the new pod
		return newPodInfo
	}
	return oldPodInfo
}
