//go:build linux
// +build linux

package checks

import (
	"testing"

	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/stretchr/testify/assert"
)

func TestTransformKubernetesTags(t *testing.T) {
	for _, tc := range []struct {
		name         string
		tags         []string
		expectedTags []string
		config       *config.AgentConfig
	}{
		{
			name:         "Should transform kubernetes tags from container and add the cluster name as a tag",
			tags:         []string{"pod_name:test-pod-name", "kube_namespace:test-kube-namespace"},
			expectedTags: []string{"pod-name:test-pod-name", "namespace:test-kube-namespace", "cluster-name:test-cluster-name"},
			config: func() *config.AgentConfig {
				cfg := config.NewDefaultAgentConfig()
				cfg.ClusterName = "test-cluster-name"
				return cfg
			}(),
		},
		{
			name:         "Should not transform any tags that are not part of the kubernetes set",
			tags:         []string{"some-other:tag", "pod_name:test-pod-name", "kube_namespace:test-kube-namespace"},
			expectedTags: []string{"some-other:tag", "pod-name:test-pod-name", "namespace:test-kube-namespace"},
			config:       config.NewDefaultAgentConfig(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tags := transformKubernetesTags(tc.tags, tc.config.ClusterName)

			assert.EqualValues(t, tc.expectedTags, tags)
		})
	}

}
