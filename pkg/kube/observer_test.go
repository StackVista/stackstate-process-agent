package kube

import (
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/obi/pkg/kubecache/informer"
)

func TestObserverCallback(t *testing.T) {
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
		DeletionTimestamp: 0,
	}
	pod1InfoDeleted := &PodInfo{
		Namespace:         pod1Info.Namespace,
		Name:              pod1Info.Name,
		Labels:            pod1Info.Labels,
		DeletionTimestamp: 323,
	}
	pod1 := &informer.ObjectMeta{
		Ips:             []string{"1.1.1.1"},
		Kind:            "Pod",
		Name:            pod1Info.Name,
		Namespace:       pod1Info.Namespace,
		Labels:          pod1Info.Labels,
		StatusTimeEpoch: int64(pod1InfoDeleted.DeletionTimestamp),
	}
	pod2Info := &PodInfo{
		Namespace:         "namespace-2",
		Name:              "pod-2",
		Labels:            map[string]string{"app": "test2"},
		DeletionTimestamp: 0,
	}
	pod2InfoDeleted := &PodInfo{
		Namespace:         pod2Info.Namespace,
		Name:              pod2Info.Name,
		Labels:            pod2Info.Labels,
		DeletionTimestamp: 4893,
	}
	pod2 := &informer.ObjectMeta{
		Ips:             []string{"2.2.2.2", "3.3.3.3"},
		Kind:            "Pod",
		Name:            pod2Info.Name,
		Namespace:       pod2Info.Namespace,
		Labels:          pod2Info.Labels,
		StatusTimeEpoch: int64(pod2InfoDeleted.DeletionTimestamp),
	}

	tests := []struct {
		name        string
		objs        []*informer.Event
		activePods  map[util.Address]*PodInfo
		deletedPods map[util.Address]*PodInfo
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
			activePods: map[util.Address]*PodInfo{
				util.AddressFromString("1.1.1.1"): pod1Info,
			},
		},
		{
			name: "Pod create with multiple IPs",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_CREATED, Resource: pod2}},
			activePods: map[util.Address]*PodInfo{
				util.AddressFromString("2.2.2.2"): pod2Info,
				util.AddressFromString("3.3.3.3"): pod2Info,
			},
		},
		{
			name: "Multiple pod create",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_CREATED, Resource: pod1}, &informer.Event{Type: informer.EventType_CREATED, Resource: pod2}},
			activePods: map[util.Address]*PodInfo{
				util.AddressFromString("1.1.1.1"): pod1Info,
				util.AddressFromString("2.2.2.2"): pod2Info,
				util.AddressFromString("3.3.3.3"): pod2Info,
			},
		},
		{
			name: "Pod update",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_UPDATED, Resource: pod1}},
			activePods: map[util.Address]*PodInfo{
				util.AddressFromString("1.1.1.1"): pod1Info,
			},
		},
		{
			name: "Pod update with multiple IPs",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_UPDATED, Resource: pod2}},
			activePods: map[util.Address]*PodInfo{
				util.AddressFromString("2.2.2.2"): pod2Info,
				util.AddressFromString("3.3.3.3"): pod2Info,
			},
		},
		{
			name: "Multiple pod update",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_UPDATED, Resource: pod1}, &informer.Event{Type: informer.EventType_UPDATED, Resource: pod2}},
			activePods: map[util.Address]*PodInfo{
				util.AddressFromString("1.1.1.1"): pod1Info,
				util.AddressFromString("2.2.2.2"): pod2Info,
				util.AddressFromString("3.3.3.3"): pod2Info,
			},
		},
		{
			name: "Pod create and delete",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_CREATED, Resource: pod1}, &informer.Event{Type: informer.EventType_DELETED, Resource: pod1}},
			deletedPods: map[util.Address]*PodInfo{
				util.AddressFromString("1.1.1.1"): pod1InfoDeleted,
			},
		},
		{
			name: "Pod create and delete a different pod not existing in the store",
			objs: []*informer.Event{&informer.Event{Type: informer.EventType_CREATED, Resource: pod1}, &informer.Event{Type: informer.EventType_DELETED, Resource: pod2}},
			activePods: map[util.Address]*PodInfo{
				util.AddressFromString("1.1.1.1"): pod1Info,
			},
			deletedPods: map[util.Address]*PodInfo{
				util.AddressFromString("2.2.2.2"): pod2InfoDeleted,
				util.AddressFromString("3.3.3.3"): pod2InfoDeleted,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// we don't want any refreshes to happen during the test
			obs, err := NewObserver(time.Duration(3 * time.Minute))
			require.NoError(t, err)

			for _, obj := range tt.objs {
				require.NoError(t, obs.On(obj))
			}
			require.Len(t, obs.activePodByIP, len(tt.activePods))
			require.Len(t, obs.deletedPodByIP, len(tt.deletedPods))

			if len(tt.activePods) > 0 {
				require.Equal(t, tt.activePods, obs.activePodByIP)
			}
			if len(tt.deletedPods) > 0 {
				require.Equal(t, tt.deletedPods, obs.deletedPodByIP)
			}
		})
	}
}

func TestResolveIpNoConflict(t *testing.T) {
	obs, err := NewObserver(time.Duration(3 * time.Minute))
	require.NoError(t, err)

	simpleIP := util.AddressFromString("1.1.1.1")
	newPodInfo := &PodInfo{
		Namespace:         "namespace-2",
		Name:              "pod-2",
		Labels:            map[string]string{"app": "test2"},
		DeletionTimestamp: 0,
	}
	obs.activePodByIP[simpleIP] = newPodInfo

	require.Equal(t, newPodInfo, obs.resolvePodByIPNoLock(simpleIP, 0, false))
}

func TestResolveIpConflict(t *testing.T) {
	obs, err := NewObserver(time.Duration(3 * time.Minute))
	require.NoError(t, err)

	conflictIP := util.AddressFromString("1.1.1.1")

	oldPodInfo := &PodInfo{
		Namespace:         "namespace-1",
		Name:              "pod-1",
		Labels:            map[string]string{"app": "test"},
		DeletionTimestamp: 12,
	}

	newPodInfo := &PodInfo{
		Namespace:         "namespace-2",
		Name:              "pod-2",
		Labels:            map[string]string{"app": "test2"},
		DeletionTimestamp: 0,
	}

	obs.deletedPodByIP[conflictIP] = oldPodInfo
	obs.activePodByIP[conflictIP] = newPodInfo

	// 1. Simulate that the pod was deleted 30 seconds ago and connection duration is 1 second (closed)
	oldPodInfo.DeletionTimestamp = uint64(time.Now().Unix() - 30)
	require.Equal(t, newPodInfo, obs.resolvePodByIPNoLock(conflictIP, 1*time.Second, true))

	// 2. Simulate that the pod was deleted 30 seconds ago and connection duration is 5 minutes (closed)
	oldPodInfo.DeletionTimestamp = uint64(time.Now().Unix() - 30)
	require.Equal(t, oldPodInfo, obs.resolvePodByIPNoLock(conflictIP, 5*time.Minute, true))

	// 3. Simulate that the pod was deleted 30 seconds after boot time and connection was created 35 seconds after boot time
	oldPodInfo.DeletionTimestamp = (obs.bootTime + 30)
	require.Equal(t, newPodInfo, obs.resolvePodByIPNoLock(conflictIP, 35*time.Second, false))

	// 4. Simulate that the pod was deleted 30 seconds after boot time and connection was created 25 seconds after boot time
	oldPodInfo.DeletionTimestamp = (obs.bootTime + 30)
	require.Equal(t, oldPodInfo, obs.resolvePodByIPNoLock(conflictIP, 25*time.Second, false))
}
