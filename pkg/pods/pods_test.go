package pods

import (
	"context"
	"github.com/DataDog/datadog-agent/pkg/util/containers"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/kubelet"
	"github.com/DataDog/datadog-agent/pkg/util/retry"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

var pod1 = &kubelet.Pod{
	Metadata: kubelet.PodMetadata{
		Name:      "pod1",
		Namespace: "ns1",
	},
	Status: kubelet.Status{
		Containers: []kubelet.ContainerStatus{
			{
				ID: "docker://pod1container1",
			},
			{
				ID: "docker://pod1container2",
			},
		},
	},
}

var pod2 = &kubelet.Pod{
	Metadata: kubelet.PodMetadata{
		Name:      "pod2",
		Namespace: "ns2",
	},
	Status: kubelet.Status{
		Containers: []kubelet.ContainerStatus{
			{
				ID: "containerd://pod2container1",
			},
			{
				ID: "containerd://pod2container2",
			},
		},
	},
}

func TestPodCache(t *testing.T) {
	ctx := context.TODO()
	podsCache := &CachedPods{
		expirationTime:   1 * time.Second,
		containerIDToPod: make(map[string]*podEntry),
		getKubeutil: func() (kubelet.KubeUtilInterface, *retry.Retrier) {
			return &kubeutilMock{
				pods: []*kubelet.Pod{pod1},
			}, nil
		},
	}

	result := podsCache.GetContainerToPodMap(ctx)
	assert.Equal(t, 2, len(result), "expected to see 2 containers returned by kubelet")
	assert.Equal(t, pod1, result["pod1container1"])
	assert.Equal(t, pod1, result["pod1container2"])

	// testing cache
	podsCache.getKubeutil = func() (kubelet.KubeUtilInterface, *retry.Retrier) {
		return &kubeutilMock{
			pods: []*kubelet.Pod{pod2},
		}, nil
	}
	time.Sleep(550 * time.Millisecond)
	result = podsCache.GetContainerToPodMap(ctx)
	assert.Equal(t, 4, len(result), "expected to see 2 cached and 2 new containers returned by kubelet")
	assert.Equal(t, pod1, result["pod1container1"])
	assert.Equal(t, pod1, result["pod1container2"])
	assert.Equal(t, pod2, result["pod2container1"])
	assert.Equal(t, pod2, result["pod2container2"])

	// testing cache expiration (pod1 should be removed)
	podsCache.getKubeutil = func() (kubelet.KubeUtilInterface, *retry.Retrier) {
		return &kubeutilMock{
			pods: []*kubelet.Pod{},
		}, nil
	}
	time.Sleep(550 * time.Millisecond)
	result = podsCache.GetContainerToPodMap(ctx)
	assert.Equal(t, 2, len(result), "expected to see cached containers of pod2")
	assert.Equal(t, 2, len(podsCache.containerIDToPod), "should be effectively removed from cache")
	assert.Equal(t, pod2, result["pod2container1"])
	assert.Equal(t, pod2, result["pod2container2"])
}

type kubeutilMock struct {
	pods []*kubelet.Pod
}

func (k *kubeutilMock) GetLocalPodList(ctx context.Context) ([]*kubelet.Pod, error) {
	return k.pods, nil
}

func (k *kubeutilMock) GetNodeInfo(ctx context.Context) (string, string, error) {

	//TODO implement me
	panic("implement me")
}

func (k *kubeutilMock) GetNodename(ctx context.Context) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (k *kubeutilMock) ForceGetLocalPodList(ctx context.Context) ([]*kubelet.Pod, error) {
	//TODO implement me
	panic("implement me")
}

func (k *kubeutilMock) GetPodForContainerID(ctx context.Context, containerID string) (*kubelet.Pod, error) {
	//TODO implement me
	panic("implement me")
}

func (k *kubeutilMock) GetStatusForContainerID(pod *kubelet.Pod, containerID string) (kubelet.ContainerStatus, error) {
	//TODO implement me
	panic("implement me")
}

func (k *kubeutilMock) GetSpecForContainerName(pod *kubelet.Pod, containerName string) (kubelet.ContainerSpec, error) {
	//TODO implement me
	panic("implement me")
}

func (k *kubeutilMock) GetPodFromUID(ctx context.Context, podUID string) (*kubelet.Pod, error) {
	//TODO implement me
	panic("implement me")
}

func (k *kubeutilMock) GetPodForEntityID(ctx context.Context, entityID string) (*kubelet.Pod, error) {
	//TODO implement me
	panic("implement me")
}

func (k *kubeutilMock) QueryKubelet(ctx context.Context, path string) ([]byte, int, error) {
	//TODO implement me
	panic("implement me")
}

func (k *kubeutilMock) GetKubeletAPIEndpoint() string {
	//TODO implement me
	panic("implement me")
}

func (k *kubeutilMock) GetRawConnectionInfo() map[string]string {
	//TODO implement me
	panic("implement me")
}

func (k *kubeutilMock) GetRawMetrics(ctx context.Context) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (k *kubeutilMock) IsAgentHostNetwork(ctx context.Context) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (k *kubeutilMock) ListContainers(ctx context.Context) ([]*containers.Container, error) {
	//TODO implement me
	panic("implement me")
}

func (k *kubeutilMock) UpdateContainerMetrics(ctrList []*containers.Container) error {
	//TODO implement me
	panic("implement me")
}

var _ kubelet.KubeUtilInterface = (*kubeutilMock)(nil)
