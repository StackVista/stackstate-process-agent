package kube

import (
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/obi/pkg/kubecache/informer"
)

// withNowFunc allows to set a custom function to get the current time. (Testing purposes)
func withNowFunc(nowFunc func() time.Time) ObserverOption {
	return func(o *Observer) {
		o.nowFunc = nowFunc
	}
}

// withBootTime allows to set a custom boot time for the observer. (Testing purposes)
func withBootTime(bootTime time.Time) ObserverOption {
	return func(o *Observer) {
		o.bootTime = bootTime.Unix()
	}
}

// withLastControlPlaneLatency allows to set a custom control plane latency for the observer. (Testing purposes)
func withLastControlPlaneLatency(latency time.Duration) ObserverOption {
	return func(o *Observer) {
		o.lastControlPlaneLatency = int64(latency.Seconds())
	}
}

func newMockClock(startTime time.Time, increment time.Duration) func() time.Time {
	// captured variable to keep track of the current time
	currentTime := startTime
	return func() time.Time {
		ret := currentTime
		currentTime = currentTime.Add(increment)
		return ret
	}
}

func (p *PodInfo) withCreationTimestamp(ts int64) *PodInfo {
	p2 := *p // create a copy to avoid modifying the original
	p2.CreationTimestamp = ts
	return &p2
}

func (p *PodInfo) withDeletionTimestamp(ts int64) *PodInfo {
	p2 := *p // create a copy to avoid modifying the original
	p2.DeletionTimestamp = ts
	return &p2
}

func TestDefaultObserver(t *testing.T) {
	reg := prometheus.NewRegistry()
	obs, err := NewObserver(reg)
	require.NoError(t, err)

	require.NotZero(t, obs.bootTime)
	require.Equal(t, defaultDeletePodsAfter, obs.deletePodsAfter)
	require.Equal(t, defaultCleanCacheInterval, obs.cleanCacheInterval)
	require.Equal(t, int64(defaultMaxEstimatedCPLatency.Seconds()), obs.lastControlPlaneLatency)

	require.Equal(t, 0.00, testutil.ToFloat64(obs.cleanedPods))
	require.Equal(t, 0.00, testutil.ToFloat64(obs.activePods))
	require.Equal(t, 0.00, testutil.ToFloat64(obs.conflictingPods))
	require.Equal(t, 0.00, testutil.ToFloat64(obs.resolutionRetries))
	require.Equal(t, 0.00, testutil.ToFloat64(obs.resolutionHits))
	require.Equal(t, 0.00, testutil.ToFloat64(obs.resolutionMisses))
	require.Equal(t, 0.00, testutil.ToFloat64(obs.resolutionAmbiguous))
}

func TestFunctionalOptionsObserver(t *testing.T) {
	cleanCacheInterval := 5 * time.Minute
	deletePodsAfter := 1 * time.Hour

	reg := prometheus.NewRegistry()
	obs, err := NewObserver(reg, WithCleanCacheInterval(cleanCacheInterval), WithDeletePodsAfter(deletePodsAfter))
	require.NoError(t, err)

	require.Equal(t, deletePodsAfter, obs.deletePodsAfter)
	require.Equal(t, cleanCacheInterval, obs.cleanCacheInterval)
}

func TestObserverCallback(t *testing.T) {
	startTime := time.Date(2025, 8, 5, 16, 30, 0, 0, time.UTC)

	node := &informer.ObjectMeta{Name: "node", Namespace: "something", Kind: "Node", Ips: []string{"10.0.0.2", "10.1.0.2"}}
	service := &informer.ObjectMeta{
		Name:      "service",
		Namespace: "namespaceA",
		Ips:       []string{"169.0.0.1", "169.0.0.2"},
		Kind:      "Service",
	}
	pod1Info := &PodInfo{
		Namespace:         "namespace-1",
		Name:              "pod-1",
		Labels:            map[string]string{"app": "test"},
		CreationTimestamp: startTime.Unix(),
		DeletionTimestamp: 0,
	}
	pod1InfoDeleted := &PodInfo{
		Namespace:         pod1Info.Namespace,
		Name:              pod1Info.Name,
		Labels:            pod1Info.Labels,
		CreationTimestamp: pod1Info.CreationTimestamp,
		DeletionTimestamp: startTime.Unix(),
	}
	pod1 := &informer.ObjectMeta{
		Ips:             []string{"1.1.1.1"},
		Kind:            "Pod",
		Name:            pod1Info.Name,
		Namespace:       pod1Info.Namespace,
		Labels:          pod1Info.Labels,
		StatusTimeEpoch: int64(pod1Info.CreationTimestamp),
	}
	pod2Info := &PodInfo{
		Namespace:         "namespace-2",
		Name:              "pod-2",
		Labels:            map[string]string{"app": "test2"},
		CreationTimestamp: startTime.Unix(),
		DeletionTimestamp: 0,
	}
	pod2InfoDeleted := &PodInfo{
		Namespace:         pod2Info.Namespace,
		Name:              pod2Info.Name,
		Labels:            pod2Info.Labels,
		CreationTimestamp: pod2Info.CreationTimestamp,
		DeletionTimestamp: startTime.Unix(),
	}
	pod2 := &informer.ObjectMeta{
		Ips:             []string{"2.2.2.2", "3.3.3.3"},
		Kind:            "Pod",
		Name:            pod2Info.Name,
		Namespace:       pod2Info.Namespace,
		Labels:          pod2Info.Labels,
		StatusTimeEpoch: int64(pod2Info.CreationTimestamp),
	}
	// Same ips of pod2
	pod3Info := &PodInfo{
		Namespace:         "namespace-3",
		Name:              "pod-3",
		Labels:            map[string]string{"app": "test3"},
		CreationTimestamp: startTime.Unix(),
		DeletionTimestamp: 0,
	}
	pod3 := &informer.ObjectMeta{
		Ips:             []string{"2.2.2.2", "3.3.3.3"},
		Kind:            "Pod",
		Name:            pod3Info.Name,
		Namespace:       pod3Info.Namespace,
		Labels:          pod3Info.Labels,
		StatusTimeEpoch: int64(pod3Info.CreationTimestamp),
	}

	tests := []struct {
		name     string
		objs     []*informer.Event
		podsByIP map[util.Address][]*PodInfo
	}{
		{
			name: "Node create",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_CREATED, Resource: node}},
		},
		{
			name: "Node update",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_UPDATED, Resource: node}},
		},
		{
			name: "Node delete",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_DELETED, Resource: node}},
		},
		{
			name: "Service create",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_CREATED, Resource: service}},
		},
		{
			name: "Service update",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_UPDATED, Resource: service}},
		},
		{
			name: "Service delete",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_DELETED, Resource: service}},
		},
		{
			name: "Invalid create",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_CREATED, Resource: nil}},
		},
		{
			name: "Invalid update",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_UPDATED, Resource: nil}},
		},
		{
			name: "Invalid delete",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_DELETED, Resource: nil}},
		},
		{
			// No pod IP, so we do nothing
			name: "Pod in host network",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
				Ips:  []string{},
				Kind: "Pod",
			}}},
		},
		{
			name: "Pod with invalid IP",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
				Ips:  []string{"not-an-ip"},
				Kind: "Pod",
			}}},
		},
		{
			name: "Pod create",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_CREATED, Resource: pod1}},
			podsByIP: map[util.Address][]*PodInfo{
				util.AddressFromString("1.1.1.1"): {pod1Info},
			},
		},
		{
			name: "Pod create with multiple IPs",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_CREATED, Resource: pod2}},
			podsByIP: map[util.Address][]*PodInfo{
				util.AddressFromString("2.2.2.2"): {pod2Info},
				util.AddressFromString("3.3.3.3"): {pod2Info},
			},
		},
		{
			name: "Multiple pod create",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_CREATED, Resource: pod1}, &informer.Event{Type: informer.EventType_CREATED, Resource: pod2}},
			podsByIP: map[util.Address][]*PodInfo{
				util.AddressFromString("1.1.1.1"): {pod1Info},
				util.AddressFromString("2.2.2.2"): {pod2Info},
				util.AddressFromString("3.3.3.3"): {pod2Info},
			},
		},
		{
			name: "Pod update",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_UPDATED, Resource: pod1}},
			podsByIP: map[util.Address][]*PodInfo{
				util.AddressFromString("1.1.1.1"): {pod1Info},
			},
		},
		{
			name: "Pod update with multiple IPs",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_UPDATED, Resource: pod2}},
			podsByIP: map[util.Address][]*PodInfo{
				util.AddressFromString("2.2.2.2"): {pod2Info},
				util.AddressFromString("3.3.3.3"): {pod2Info},
			},
		},
		{
			name: "Multiple pod update",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_UPDATED, Resource: pod1}, &informer.Event{Type: informer.EventType_UPDATED, Resource: pod2}},
			podsByIP: map[util.Address][]*PodInfo{
				util.AddressFromString("1.1.1.1"): {pod1Info},
				util.AddressFromString("2.2.2.2"): {pod2Info},
				util.AddressFromString("3.3.3.3"): {pod2Info},
			},
		},
		{
			name: "Pod create and delete",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_CREATED, Resource: pod1}, &informer.Event{Type: informer.EventType_DELETED, Resource: pod1}},
			podsByIP: map[util.Address][]*PodInfo{
				util.AddressFromString("1.1.1.1"): {pod1InfoDeleted},
			},
		},
		{
			name: "Pod create and delete a different pod not existing in the store",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_CREATED, Resource: pod2}, &informer.Event{Type: informer.EventType_DELETED, Resource: pod1}},
			podsByIP: map[util.Address][]*PodInfo{
				util.AddressFromString("2.2.2.2"): {pod2Info},
				util.AddressFromString("3.3.3.3"): {pod2Info},
				util.AddressFromString("1.1.1.1"): {&PodInfo{
					Namespace: pod1Info.Namespace,
					Name:      pod1Info.Name,
					Labels:    pod1Info.Labels,
					// if we add a pod in the cache from a deleted event we put the creation timestamp to 0
					CreationTimestamp: 0,
					DeletionTimestamp: startTime.Unix(),
				}},
			},
		},
		{
			name: "Delete pod and create it with the same IP",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_CREATED, Resource: pod2}, &informer.Event{Type: informer.EventType_DELETED, Resource: pod2}, &informer.Event{Type: informer.EventType_CREATED, Resource: pod3}},
			podsByIP: map[util.Address][]*PodInfo{
				util.AddressFromString("2.2.2.2"): {pod2InfoDeleted, pod3Info},
				util.AddressFromString("3.3.3.3"): {pod2InfoDeleted, pod3Info},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			obs, err := NewObserver(reg,
				// we don't want a cache cleanup in these tests
				WithCleanCacheInterval(10*time.Minute),
				withNowFunc(func() time.Time {
					// we always return the same start time for consistency in tests
					return startTime
				}),
			)
			require.NoError(t, err)

			for _, obj := range tt.objs {
				require.NoError(t, obs.On(obj))
			}
			require.Len(t, obs.podsByIP, len(tt.podsByIP))

			if len(tt.podsByIP) > 0 {
				require.Equal(t, tt.podsByIP, obs.podsByIP)
			}
		})
	}
}

func TestResolvePodByIP(t *testing.T) {
	pod1IP := util.AddressFromString("1.1.1.1")
	pod1Info := &PodInfo{
		Namespace: "namespace-1",
		Name:      "pod-1",
		Labels:    map[string]string{"app": "test1"},
	}
	pod2Info := &PodInfo{
		Namespace: "namespace-2",
		Name:      "pod-2",
		Labels:    map[string]string{"app": "test2"},
	}

	tests := []struct {
		name                    string
		time                    time.Time
		bootTime                time.Time
		lastControlPlaneLatency time.Duration
		maxControlPlaneLatency  time.Duration
		nsFromBoot              time.Duration
		podsByIP                map[util.Address][]*PodInfo
		expectedInfoPos         int
		expectedRetry           bool
		resolutionHits          float64
		resolutionRetries       float64
		resolutionMisses        float64
		resolutionAmbiguous     float64
	}{
		{
			name:                    "retry",
			bootTime:                time.Unix(10, 0),
			nsFromBoot:              5 * time.Second,
			lastControlPlaneLatency: 60 * time.Second,
			time:                    time.Unix(30, 0),
			podsByIP: map[util.Address][]*PodInfo{
				pod1IP: {pod1Info.withCreationTimestamp(14).withDeletionTimestamp(0)},
			},
			expectedInfoPos:   -1,
			expectedRetry:     true,
			resolutionRetries: 1.0,
		},
		{
			name:                    "no pod into the cache",
			bootTime:                time.Unix(10, 0),
			nsFromBoot:              5 * time.Second,
			lastControlPlaneLatency: 10 * time.Second,
			time:                    time.Unix(30, 0),
			podsByIP:                make(map[util.Address][]*PodInfo),
			expectedInfoPos:         -1,
			expectedRetry:           false,
			resolutionMisses:        1.0,
		},
		{
			name:                    "creation time before first pod",
			bootTime:                time.Unix(10, 0),
			nsFromBoot:              5 * time.Second,
			lastControlPlaneLatency: 10 * time.Second,
			time:                    time.Unix(40, 0),
			podsByIP: map[util.Address][]*PodInfo{
				pod1IP: {pod1Info.withCreationTimestamp(26).withDeletionTimestamp(0)},
			},
			expectedInfoPos:  -1,
			expectedRetry:    false,
			resolutionMisses: 1.0,
		},
		{
			name:                    "creation time between first pod and second pod, first nearer",
			bootTime:                time.Unix(10, 0),
			nsFromBoot:              20 * time.Second,
			lastControlPlaneLatency: 1 * time.Second,
			time:                    time.Unix(60, 0),
			podsByIP: map[util.Address][]*PodInfo{
				pod1IP: {
					pod1Info.withCreationTimestamp(10).withDeletionTimestamp(27),
					pod2Info.withCreationTimestamp(35).withDeletionTimestamp(0),
				},
			},
			expectedInfoPos:  -1,
			expectedRetry:    false,
			resolutionMisses: 1.0,
		},
		{
			name:                    "creation time between first pod and second pod, second nearer",
			bootTime:                time.Unix(10, 0),
			nsFromBoot:              20 * time.Second,
			lastControlPlaneLatency: 1 * time.Second,
			time:                    time.Unix(60, 0),
			podsByIP: map[util.Address][]*PodInfo{
				pod1IP: {
					pod1Info.withCreationTimestamp(10).withDeletionTimestamp(27),
					pod2Info.withCreationTimestamp(32).withDeletionTimestamp(0),
				},
			},
			expectedInfoPos:  -1,
			expectedRetry:    false,
			resolutionMisses: 1.0,
		},
		{
			name:                    "creation time inside a pod still alive",
			bootTime:                time.Unix(10, 0),
			nsFromBoot:              20 * time.Second,
			lastControlPlaneLatency: 1 * time.Second,
			time:                    time.Unix(60, 0),
			podsByIP: map[util.Address][]*PodInfo{
				pod1IP: {
					pod1Info.withCreationTimestamp(10).withDeletionTimestamp(0),
				},
			},
			expectedInfoPos: 0,
			expectedRetry:   false,
			resolutionHits:  1.0,
		},
		{
			name:                    "creation time inside a pod already deleted, only 1 pod",
			bootTime:                time.Unix(10, 0),
			nsFromBoot:              20 * time.Second,
			lastControlPlaneLatency: 1 * time.Second,
			time:                    time.Unix(60, 0),
			podsByIP: map[util.Address][]*PodInfo{
				pod1IP: {
					pod1Info.withCreationTimestamp(10).withDeletionTimestamp(58),
				},
			},
			expectedInfoPos: 0,
			expectedRetry:   false,
			resolutionHits:  1.0,
		},
		{
			name:                    "creation time inside a pod already deleted, no overlapping",
			bootTime:                time.Unix(10, 0),
			nsFromBoot:              20 * time.Second,
			lastControlPlaneLatency: 1 * time.Second,
			time:                    time.Unix(120, 0),
			podsByIP: map[util.Address][]*PodInfo{
				pod1IP: {
					pod1Info.withCreationTimestamp(10).withDeletionTimestamp(58),
					pod2Info.withCreationTimestamp(64).withDeletionTimestamp(0),
				},
			},
			expectedInfoPos: 0,
			expectedRetry:   false,
			resolutionHits:  1.0,
		},
		{
			name:                    "creation time inside 2 pods, inside the first one",
			bootTime:                time.Unix(10, 0),
			nsFromBoot:              20 * time.Second,
			lastControlPlaneLatency: 5 * time.Second,
			maxControlPlaneLatency:  10 * time.Second,
			time:                    time.Unix(120, 0),
			podsByIP: map[util.Address][]*PodInfo{
				pod1IP: {
					pod1Info.withCreationTimestamp(10).withDeletionTimestamp(37),
					pod2Info.withCreationTimestamp(40).withDeletionTimestamp(0),
				},
			},
			expectedInfoPos:     0,
			expectedRetry:       false,
			resolutionAmbiguous: 1.0,
		},
		{
			name:                    "creation time inside 2 pods, inside the second one",
			bootTime:                time.Unix(10, 0),
			nsFromBoot:              20 * time.Second,
			lastControlPlaneLatency: 5 * time.Second,
			maxControlPlaneLatency:  10 * time.Second,
			time:                    time.Unix(120, 0),
			podsByIP: map[util.Address][]*PodInfo{
				pod1IP: {
					pod1Info.withCreationTimestamp(10).withDeletionTimestamp(31),
					pod2Info.withCreationTimestamp(32).withDeletionTimestamp(0),
				},
			},
			expectedInfoPos:     1,
			expectedRetry:       false,
			resolutionAmbiguous: 1.0,
		},
		{
			name:                    "creation time inside 2 pods, outside both, pick closest",
			bootTime:                time.Unix(10, 0),
			nsFromBoot:              20 * time.Second,
			lastControlPlaneLatency: 5 * time.Second,
			maxControlPlaneLatency:  10 * time.Second,
			time:                    time.Unix(120, 0),
			podsByIP: map[util.Address][]*PodInfo{
				pod1IP: {
					pod1Info.withCreationTimestamp(10).withDeletionTimestamp(31),
					pod2Info.withCreationTimestamp(40).withDeletionTimestamp(0),
				},
			},
			expectedInfoPos:     0,
			expectedRetry:       false,
			resolutionAmbiguous: 1.0,
		},
		{
			name:                    "creation time after the last pod",
			bootTime:                time.Unix(10, 0),
			nsFromBoot:              45 * time.Second,
			lastControlPlaneLatency: 5 * time.Second,
			time:                    time.Unix(120, 0),
			podsByIP: map[util.Address][]*PodInfo{
				pod1IP: {
					pod1Info.withCreationTimestamp(10).withDeletionTimestamp(33),
					pod2Info.withCreationTimestamp(32).withDeletionTimestamp(40),
				},
			},
			expectedInfoPos:  -1,
			expectedRetry:    false,
			resolutionMisses: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := prometheus.NewRegistry()

			// this is a workaround to avoid setting the max control plane latency in each test case.
			if tt.maxControlPlaneLatency == 0 {
				tt.maxControlPlaneLatency = tt.lastControlPlaneLatency
			}

			obs, err := NewObserver(reg,
				withBootTime(tt.bootTime),
				withLastControlPlaneLatency(tt.lastControlPlaneLatency),
				WithMaxControlPlaneLatency(tt.maxControlPlaneLatency),
				withNowFunc(func() time.Time { return tt.time }))
			require.NoError(t, err)

			obs.podsByIP = tt.podsByIP

			info, retry := obs.resolvePodByIPNoLock(pod1IP, tt.nsFromBoot)
			require.Equal(t, tt.expectedRetry, retry)
			if tt.expectedInfoPos == -1 {
				require.Nil(t, info)
			} else {
				require.Equal(t, tt.podsByIP[pod1IP][tt.expectedInfoPos], info)
			}

			require.Equal(t, tt.resolutionHits, testutil.ToFloat64(obs.resolutionHits))
			require.Equal(t, tt.resolutionRetries, testutil.ToFloat64(obs.resolutionRetries))
			require.Equal(t, tt.resolutionMisses, testutil.ToFloat64(obs.resolutionMisses))
			require.Equal(t, tt.resolutionAmbiguous, testutil.ToFloat64(obs.resolutionAmbiguous))
		})
	}
}

func TestCleanup(t *testing.T) {
	IP1 := util.AddressFromString("1.1.1.1")
	IP2 := util.AddressFromString("1.1.1.2")
	IP3 := util.AddressFromString("1.1.1.3")
	podInfo := &PodInfo{
		Namespace:         "namespace",
		Name:              "pod",
		Labels:            map[string]string{"app": "test"},
		CreationTimestamp: 14,
		DeletionTimestamp: 0,
	}

	tests := []struct {
		name        string
		podsByIP    map[util.Address][]*PodInfo
		cleanedPods float64
		inCachePods float64
	}{
		{
			name: "no deletion",
			podsByIP: map[util.Address][]*PodInfo{
				IP1: {
					podInfo.withCreationTimestamp(14).withDeletionTimestamp(0),
				},
				IP2: {
					podInfo.withCreationTimestamp(20).withDeletionTimestamp(0),
				},
				IP3: {
					podInfo.withCreationTimestamp(30).withDeletionTimestamp(0),
				},
			},
			cleanedPods: 0.0,
			inCachePods: 3.0,
		},
		{
			name: "deletions",
			podsByIP: map[util.Address][]*PodInfo{
				IP1: {
					podInfo.withCreationTimestamp(1).withDeletionTimestamp(10),  // deleted
					podInfo.withCreationTimestamp(12).withDeletionTimestamp(20), // deleted
					podInfo.withCreationTimestamp(26).withDeletionTimestamp(44), // not deleted
					podInfo.withCreationTimestamp(45).withDeletionTimestamp(0),  // not deleted
				},
				IP2: {
					podInfo.withCreationTimestamp(20).withDeletionTimestamp(44), // not deleted
				},
				IP3: {
					podInfo.withCreationTimestamp(3).withDeletionTimestamp(30), // deleted
					podInfo.withCreationTimestamp(31).withDeletionTimestamp(0), // not deleted
				},
			},
			cleanedPods: 3.0,
			inCachePods: 4.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			obs, err := NewObserver(reg,
				withNowFunc(func() time.Time { return time.Unix(60, 0) }),
				WithDeletePodsAfter(30*time.Second),
			)
			require.NoError(t, err)

			obs.podsByIP = tt.podsByIP

			obs.cleanup()

			require.Equal(t, tt.cleanedPods, testutil.ToFloat64(obs.cleanedPods))
			require.Equal(t, tt.inCachePods, testutil.ToFloat64(obs.activePods))
		})
	}
}
