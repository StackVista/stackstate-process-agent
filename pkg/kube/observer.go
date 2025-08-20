package kube

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/process/util"
	log "github.com/cihub/seelog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/shirou/gopsutil/v4/host"

	"go.opentelemetry.io/obi/pkg/kubecache/informer"
)

const (
	defaultDeletePodsAfter       = 2 * time.Minute
	defaultCleanCacheInterval    = 10 * time.Minute
	defaultMaxEstimatedCPLatency = 5 * time.Second

	prometheusNamespace = "stackstate_process_agent"
	prometheusSubsystem = "observer"
)

var exceedCPLatencyWarning sync.Once

// Observer implements the informer.Observer interface to observe Kubernetes events.
type Observer struct {
	// when we receive an event from the informer, we use a write lock.
	// when we want to read from the cache, we need to acquire a read lock
	access sync.RWMutex

	// An LRU cache doesn't help here because we cannot remove entries based on time, the pod could be still valid.
	// this maps grows indefinitely, we expose metrics and we try to clean it up periodically.
	podsByIP map[util.Address][]*PodInfo

	// we need the boot time because all what we receive from ebpf is the time in nanoseconds since boot
	bootTime int64

	// Last time we refreshed the deleted pods cache
	lastCacheClean time.Time

	// real control plane latency that we recompute at each new event from the control plane.
	// if we have too much variation in the control plane latency, we should compute the average.
	lastControlPlaneLatency int64

	// Configurable by the user
	cleanCacheInterval time.Duration
	deletePodsAfter    time.Duration
	// maximum latency we assume can happen between control plane and our node.
	maxControlPlaneLatency int64
	// just used for testing
	nowFunc func() time.Time

	// Metrics
	controlPlaneLatency prometheus.Histogram
	activePods          prometheus.Gauge
	cleanedPods         prometheus.Counter
	conflictingPods     prometheus.Counter
	resolutionRetries   prometheus.Counter
	resolutionHits      prometheus.Counter
	resolutionAmbiguous prometheus.Counter
	resolutionMisses    prometheus.Counter
}

// ObserverOption is a functional option for configuring the Observer.
type ObserverOption func(*Observer)

// WithCleanCacheInterval sets the interval for cleaning the cache.
func WithCleanCacheInterval(interval time.Duration) ObserverOption {
	return func(o *Observer) {
		o.cleanCacheInterval = interval
	}
}

// WithDeletePodsAfter sets the duration after which deleted pods are removed from the cache.
func WithDeletePodsAfter(deleteAfter time.Duration) ObserverOption {
	return func(o *Observer) {
		o.deletePodsAfter = deleteAfter
	}
}

// WithMaxControlPlaneLatency sets the maximum allowed control plane latency.
func WithMaxControlPlaneLatency(maxLatency time.Duration) ObserverOption {
	return func(o *Observer) {
		o.maxControlPlaneLatency = int64(maxLatency.Seconds())
	}
}

// WithPodDebugEndpoint adds an HTTP endpoint to expose the current pods in the cache.
func WithPodDebugEndpoint() ObserverOption {
	return func(o *Observer) {
		http.HandleFunc("/pods", func(w http.ResponseWriter, r *http.Request) {
			o.access.RLock()
			defer o.access.RUnlock()

			// Build a serializable map[string][]*PodInfo where the key is the IP string.
			out := make(map[string][]*PodInfo, len(o.podsByIP))
			for addr, pods := range o.podsByIP {
				out[addr.String()] = pods
			}

			w.Header().Set("Content-Type", "application/json")
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			if err := enc.Encode(out); err != nil {
				http.Error(w, fmt.Sprintf("failed to encode pods json: %v", err), http.StatusInternalServerError)
				return
			}
		})
	}
}

// NewObserver creates a new Observer instance.
func NewObserver(reg prometheus.Registerer, opts ...ObserverOption) (*Observer, error) {
	// we need the boot time because all what we receive from ebpf is the time in nanoseconds since boot
	bt, err := host.BootTime()
	if err != nil {
		return nil, fmt.Errorf("failed to get boot time: %w", err)
	}
	log.Infof("Host boot time: %v", time.Unix(int64(bt), 0))

	obs := &Observer{
		podsByIP:                make(map[util.Address][]*PodInfo),
		bootTime:                int64(bt),
		lastControlPlaneLatency: int64(defaultMaxEstimatedCPLatency.Seconds()),
		maxControlPlaneLatency:  int64(defaultMaxEstimatedCPLatency.Seconds()),
		cleanCacheInterval:      defaultCleanCacheInterval,
		deletePodsAfter:         defaultDeletePodsAfter,
		nowFunc:                 time.Now,

		controlPlaneLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: prometheusNamespace,
			Subsystem: prometheusSubsystem,
			Name:      "control_plane_latency_seconds",
			Help:      "Difference between the time when the pod was created by the control plane and the time when it was observed by the observer.",
		}),

		activePods: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: prometheusNamespace,
			Subsystem: prometheusSubsystem,
			Name:      "active_pods",
			Help:      "Number of active pods in the cache.",
		}),

		cleanedPods: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: prometheusNamespace,
			Subsystem: prometheusSubsystem,
			Name:      "cleaned_pods",
			Help:      "Number of pods evicted during the cleanup process.",
		}),

		conflictingPods: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: prometheusNamespace,
			Subsystem: prometheusSubsystem,
			Name:      "conflicting_pods",
			Help:      "Number of pods that reuse the same IP address of other pods in a short period of time.",
		}),

		resolutionRetries: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: prometheusNamespace,
			Subsystem: prometheusSubsystem,
			Name:      "resolution_retries",
			Help:      "Number of times the observer had to retry resolving a pod's IP address.",
		}),

		resolutionHits: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: prometheusNamespace,
			Subsystem: prometheusSubsystem,
			Name:      "resolution_hits",
			Help:      "Number of times the observer successfully resolved a pod's IP address.",
		}),

		resolutionAmbiguous: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: prometheusNamespace,
			Subsystem: prometheusSubsystem,
			Name:      "resolution_ambiguous",
			Help:      "Number of times the observer resolved an IP address but the resolution was ambiguous.",
		}),

		resolutionMisses: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: prometheusNamespace,
			Subsystem: prometheusSubsystem,
			Name:      "resolution_misses",
			Help:      "Number of times the observer failed to resolve a pod's IP address.",
		}),
	}
	reg.MustRegister(obs.controlPlaneLatency, obs.activePods, obs.cleanedPods, obs.conflictingPods, obs.resolutionRetries, obs.resolutionHits, obs.resolutionAmbiguous, obs.resolutionMisses)

	// Apply options
	for _, opt := range opts {
		opt(obs)
	}

	// update it after we apply the options, since nowFunc can be overridden
	obs.lastCacheClean = obs.nowFunc()

	log.Infof("Observer created with clean cache interval: %s, delete pods after: %s", obs.cleanCacheInterval, obs.deletePodsAfter)
	return obs, nil
}

func eventName(eventType informer.EventType) string {
	if name, ok := informer.EventType_name[int32(eventType)]; ok {
		return name
	}
	return fmt.Sprintf("unknown_event_%d", eventType)
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
	case informer.EventType_UPDATED, informer.EventType_CREATED, informer.EventType_DELETED:
		o.processPodMeta(event.Resource, event.Type)

	// At the moment we don't need this one. Used only by the original OBI implementation
	// case informer.EventType_SYNC_FINISHED

	default:
	}
	return nil
}

func (o *Observer) cleanup() {
	// deadline should be enough time to allow correlations on deleted pods
	now := o.nowFunc().Unix()
	deadline := int64(o.deletePodsAfter.Seconds())

	cleanedPods := 0
	inCachePods := 0

	for _, podInfos := range o.podsByIP {
		for _, info := range podInfos {
			// The oldest pod should be the first in the slice, so we can break the loop as soon as we find a pod that is not deleted or that doesn't exceed the deadline.
			if info.DeletionTimestamp == 0 ||
				info.DeletionTimestamp+deadline > now {
				break
			}

			podInfos = podInfos[1:]
			cleanedPods++
			log.Debugf("Removing deleted pod %s/%s from cache", info.Namespace, info.Name)
		}
		inCachePods += len(podInfos)
	}

	log.Infof("Cleaning up pods cache: deleted pods: %d, remaining in cache: %d", cleanedPods, inCachePods)

	o.cleanedPods.Add(float64(cleanedPods))
	// update the active pods gauge
	o.activePods.Set(float64(inCachePods))
}

func (o *Observer) processPodMeta(meta *informer.ObjectMeta, eventType informer.EventType) {
	o.access.Lock()
	defer o.access.Unlock()

	if o.lastCacheClean.Add(o.cleanCacheInterval).Before(o.nowFunc()) {
		o.cleanup()
		o.lastCacheClean = o.nowFunc()
	}

	// This is possible in at least two cases:
	// 1. We receive a pod creation event for a new pod.
	// 2. The pod is running in the hostNetwork. The acutal informer implementation does not send the IPs for hostNetwork pods.
	//    but for us this is not an issue because the ip would be the Ip of the node so we don't need it.
	if len(meta.Ips) == 0 {
		return
	}

	// We need an array because a pod can have more than one IP, ipv6/ipv4, we use a separate entry for each IP.
	// We should update only if the labels are different, but for now we just overwrite every time.
outerLoop:
	for _, ip := range meta.Ips {
		addr := util.AddressFromString(ip)
		if !addr.IsValid() {
			log.Warnf("[%s] invalid IP address %s for pod %s/%s", eventName(eventType), ip, meta.Namespace, meta.Name)
			continue
		}

		log.Debugf("[%s] pod to store: %s/%s with IP %v and labels %v", eventName(eventType),
			meta.Namespace, meta.Name, ip, stringifyPodLabels(meta.Labels))

		now := o.nowFunc().Unix()
		if eventType != informer.EventType_CREATED {
			// We receive here CREATE events only at the beginning when we start the agent.
			// Their initial timestamp is the time the pod started in the cluster so it's not useful to compare it with `now`
			o.lastControlPlaneLatency = now - meta.StatusTimeEpoch
			o.controlPlaneLatency.Observe(float64(o.lastControlPlaneLatency))
			if o.lastControlPlaneLatency > o.maxControlPlaneLatency {
				exceedCPLatencyWarning.Do(func() {
					log.Warnf("control plane latency exceed expected one: %d s > %d s", o.lastControlPlaneLatency, o.maxControlPlaneLatency)
				})
			}
		}
		// we need to understand if this is a new pod or an update of an existing pod
		for _, podInfo := range o.podsByIP[addr] {
			if podInfo.Name == meta.Name && podInfo.Namespace == meta.Namespace {
				// this is an update of an existing pod, we just update the labels
				podInfo.Labels = stringifyPodLabels(meta.Labels)
				if eventType == informer.EventType_DELETED {
					podInfo.DeletionTimestamp = now
				}
				continue outerLoop
			}
		}

		deletionTs := int64(0)
		creationTs := now
		// it shouldn't happen but we want to manage also this case in which we receive a deletion event without a previous create event.
		if eventType == informer.EventType_DELETED {
			deletionTs = now
			creationTs = 0 // we don't know when the pod was created, so we set it to 0
		}

		if len(o.podsByIP[addr]) > 1 {
			o.conflictingPods.Inc()
		}
		o.activePods.Inc()

		// Usually we create a new pod on the first update event we receive for the pod, since the create event doesn't have pod IPs and so we don't reach this code.
		o.podsByIP[addr] = append(o.podsByIP[addr], &PodInfo{
			Name:              meta.Name,
			Namespace:         meta.Namespace,
			Labels:            stringifyPodLabels(meta.Labels),
			CreationTimestamp: creationTs,
			DeletionTimestamp: deletionTs,
		})
	}
}

// ConnectionNeedsRetry returns true if the connection needs to be retried.
func (o *Observer) ConnectionNeedsRetry(nsFromBoot time.Duration) bool {
	connCreationTime := o.bootTime + int64(nsFromBoot.Seconds())
	if connCreationTime > o.nowFunc().Unix()-o.maxControlPlaneLatency {
		o.resolutionRetries.Inc()
		return true
	}
	return false
}

// ResolvePodsByIPs resolves the pods by their IPs, returning the PodInfo for each IP.
func (o *Observer) ResolvePodsByIPs(srcIP, dstIP util.Address, nsFromBoot time.Duration) (*PodInfo, *PodInfo) {
	o.access.RLock()
	defer o.access.RUnlock()
	return o.resolvePodByIPNoLock(srcIP, nsFromBoot), o.resolvePodByIPNoLock(dstIP, nsFromBoot)
}

// ResolvePodByIP resolves a pod by its IP, returning the PodInfo for the IP.
func (o *Observer) ResolvePodByIP(ip util.Address, nsFromBoot time.Duration) *PodInfo {
	o.access.RLock()
	defer o.access.RUnlock()
	return o.resolvePodByIPNoLock(ip, nsFromBoot)
}

func (o *Observer) resolvePodByIPNoLock(ip util.Address, nsFromBoot time.Duration) *PodInfo {
	connCreationTime := o.bootTime + int64(nsFromBoot.Seconds())
	lastControlPlaneLatency := o.lastControlPlaneLatency
	maxControlPlaneLatency := o.maxControlPlaneLatency

	podSlice := o.podsByIP[ip]
	if len(podSlice) == 0 {
		o.resolutionMisses.Inc()
		return nil
	}

	matchingPods := make([]*PodInfo, 0)
	// Since we are doing `podInfo.CreationTimestamp-maxControlPlaneLatency` the pods could overlap between them, so the connection could match multiple pods.
	// C1 ----------- C2 --c- D1 ------------- D2
	for _, podInfo := range podSlice {
		if podInfo.CreationTimestamp-maxControlPlaneLatency <= connCreationTime && (podInfo.DeletionTimestamp == 0 || podInfo.DeletionTimestamp >= connCreationTime) {
			matchingPods = append(matchingPods, podInfo)
		}
	}

	if len(matchingPods) == 1 {
		o.resolutionHits.Inc()
		return matchingPods[0]
	}

	if len(matchingPods) == 0 {
		// c -> connection creation time.
		// C -> pod creation time as observed by us (so it includes the estimated latency).
		// D -> pod deletion time as observed by us (so it includes the estimated latency).
		// M -> max control plane latency.
		//
		// If we arrive here it means the pod slice is not empty but we cannot match a pod
		// We have at least the following cases:
		// 1.connection before first pod: c   C-M-----------------D
		// 2.connection between 2 pods: C-M-----------------D c C-M------------------D
		// 3.connection after last pod: C-M-----------------D c
		log.Infof("connection (IP %s, creation ts: %v) doesn't fall in any pod range. %v", ip, time.Unix(connCreationTime, 0), podSlice)
		o.resolutionMisses.Inc()
		return nil
	}

	// This is the tricky case. We got multiple potential matching pods (this can happen because we take potential network delays into account when calculating hits).
	// We use the most accurate delay calculation here to find the pod which matches closest and call it good.
	o.resolutionAmbiguous.Inc()

	var closestMatchingPod *PodInfo
	var closestPodDistance int64 = math.MaxInt64
	var podTimeDistance int64

	// In this for loop we don't do `podInfo.CreationTimestamp-maxControlPlaneLatency` so pods don't overlap.
	// To create more realistic pod intervals we can subtract the last control plane latency from the pod creation and deletion timestamps. Instead of doing that we add the last control plane latency to the connection creation time, because it is easier.
	connCreationTime += lastControlPlaneLatency

	// From the previous situation: C1 ----------- C2 --c- D1 ------------- D2
	// We should obtain similar situations:
	// * C1 ----------- D1 c C2 ------------ D2
	// * C1 ----------c D1 C2 ------------ D2
	// * C1 ----------- D1 C2 c----------- D2
	// * c C1 - D1 C2 - D2
	for _, matchingPod := range matchingPods {

		if matchingPod.CreationTimestamp > connCreationTime {
			// Conntime is before create
			podTimeDistance = matchingPod.CreationTimestamp - connCreationTime
		} else if matchingPod.DeletionTimestamp != 0 && matchingPod.DeletionTimestamp < connCreationTime {
			// Conntime is after delete
			podTimeDistance = connCreationTime - matchingPod.DeletionTimestamp
		} else {
			// Conntime is within the pod create/delete. We can do an early exit because we know pod
			// times are disjoint
			log.Infof("connection (IP %s, creation ts: %v) after disambiguation falls into pod '%s'. Available pods: %v", ip, time.Unix(connCreationTime, 0), matchingPod, podSlice)
			return matchingPod
		}

		if podTimeDistance < closestPodDistance {
			closestMatchingPod = matchingPod
			closestPodDistance = podTimeDistance
		}
	}
	log.Infof("connection (IP %s, creation ts: %v) after disambiguation doesn't fall in any pod. Pick the closest one '%s'. Available pods: %v", ip, time.Unix(connCreationTime, 0), closestMatchingPod, podSlice)
	return closestMatchingPod
}

// This method models another resolution algorithm where we always try to match the closest pod to the
// connection creation time if there is at least one pod associated to the IP. With the current model
// connections that are "too far" from pods are not correlated even if we have pods in the cache.
//
// func (o *Observer) resolvePodByIPNoLockv2(ip util.Address, nsFromBoot time.Duration) (*PodInfo, bool) {
// 	connCreationTime := o.bootTime + int64(nsFromBoot.Seconds())
// 	controlPlaneLatency := o.lastControlPlaneLatency

// 	// we do this to wait for possible control plane events that could be delayed.
// 	if connCreationTime > o.nowFunc().Unix()-controlPlaneLatency {
// 		// we need to store the connection and retry later
// 		o.resolutionRetries.Inc()
// 		return nil, true
// 	}

// 	podSlice := o.podsByIP[ip]
// 	if len(podSlice) == 0 {
// 		o.resolutionMisses.Inc()
// 		return nil, false
// 	}

// 	// c -> connection creation time.
// 	// C -> pod creation time as observed by us (so it includes the estimated latency).
// 	// D -> pod deletion time as observed by us (so it includes the estimated latency).
// 	// ++ -> latency we assume can happen between control plane and our node.
// 	//
// 	// Possible cases:
// 	// 1.connection before first pod: c ++C ----------------- ++D
// 	// 2.connection between 2 pods: ++C ----------------- ++D  c ++C ------------------ ++D
// 	// 3.connection inside a pod still alive: ++C --------c--------
// 	// 4.connection inside a pod alredy delete: ++C --------c-------- ++D
// 	// 5.connection inside 2 pods. This case is artificially created by the fact that we use the estimated latency to resolve pods.
// 	//   A wrong latency computation can lead to this case. ++C1 ----------- ++C2 --c- ++D1 ------------- ++D2
// 	// 6.connection after last pod: ++C ----------------- ++D c

// 	for i, podInfo := range podSlice {
// 		estimatedPodCreateTime := podInfo.CreationTimestamp - controlPlaneLatency
// 		if connCreationTime < estimatedPodCreateTime {
// 			// We enter this if when:
// 			// - The connection creation time is before the first pod creation time. (case 1)
// 			// - The connection creation time is after the pod deletion time of the previous
// 			// and before the pod creation time of the current one. So in the middle of 2 pods. (case 2)
// 			//
// 			// These are clearly ambiguous resolutions.
// 			// todo!: A metric is ok but probably we should have a way to correlate that this specific connection is ambiguous.
// 			o.resolutionAmbiguous.Inc()

// 			// We try to pick the nearest pod. 2 cases:
// 			// 1. if the pod is the first one, we assign the connection to it.
// 			if i == 0 {
// 				log.Infof("connection (IP %s) with creation time before the first pod. Assign to it the first pod (%s).", ip, podInfo)
// 				return podInfo, false
// 			}

// 			// 2. if the pod is not the first one, we find the nearest pod and return it.
// 			chosenPod := podInfo
// 			if estimatedPodCreateTime-connCreationTime >= connCreationTime-podSlice[i-1].DeletionTimestamp {
// 				// The previous pod was closer to the connection creation time.
// 				chosenPod = podSlice[i-1]
// 			}
// 			log.Infof("connection (IP %s) with creation time in the middle of 2 pods(%s <-> %s). Assign to pod (%s).", ip, podSlice[i-1], podInfo, chosenPod)
// 			return chosenPod, false
// 		}

// 		// if we arrive here it means `connCreationTime >= estimatedPodCreateTime`

// 		if podInfo.DeletionTimestamp == 0 {
// 			// The connection creation time is after the pod creation time and the pod is still running. (case 3)
// 			o.resolutionHits.Inc()
// 			return podInfo, false
// 		}

// 		if connCreationTime > podInfo.DeletionTimestamp {
// 			// The connection doesn't match the pod because it was deleted before the connection creation time.
// 			continue
// 		}

// 		// if we arrive here it means `connCreationTime <= podInfo.DeletionTimestamp`

// 		// We have 2 cases here:
// 		// 1. if the connection is only inside this pod and not the next one, we return it. (case 4)
// 		//    The connection is for sure inside one pod if it is the last one.
// 		if i == len(podSlice)-1 ||
// 			connCreationTime < podSlice[i+1].CreationTimestamp-controlPlaneLatency {
// 			o.resolutionHits.Inc()
// 			return podInfo, false
// 		}

// 		// 2. The connection is inside 2 pods (case 5).
// 		o.resolutionAmbiguous.Inc()
// 		estimatedPodCreateTime = podSlice[i+1].CreationTimestamp - controlPlaneLatency
// 		chosenPod := podSlice[i+1]
// 		if connCreationTime-estimatedPodCreateTime >= podInfo.DeletionTimestamp-connCreationTime {
// 			// The current pod is closer to the connection creation time.
// 			chosenPod = podInfo
// 		}
// 		log.Infof("connection (IP %s) with creation time in the middle of 2 pods(%s <-> %s). Assign to pod (%s).", ip, podInfo, podSlice[i+1], chosenPod)
// 		return chosenPod, false
// 	}

// 	// If we arrive here it means the connection is after the last pod (case 6)
// 	o.resolutionAmbiguous.Inc()
// 	log.Infof("connection (IP %s) with creation time after the last pod. Assign to it the last pod (%s).", ip, podSlice[len(podSlice)-1])
// 	return podSlice[len(podSlice)-1], false
// }
