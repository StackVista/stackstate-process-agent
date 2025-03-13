package config

import (
	"testing"

	modelconfig "github.com/DataDog/datadog-agent/pkg/config/model"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/stretchr/testify/assert"
	"strings"
)

// We test the unique configs we override in datadog to be sure they are always there between versions.
func TestConfigLoading(t *testing.T) {
	conf := modelconfig.NewConfig("test-config", "DD", strings.NewReplacer(".", "_"))
	pkgconfigsetup.InitConfig(conf)
	conf.SetConfigFile("")

	expectedSocketPath := "/var/run/cri.sock"
	expectedKubeletHost := "http://localhost:10255"
	t.Setenv("DD_CRI_SOCKET_PATH", expectedSocketPath)
	t.Setenv("DD_KUBERNETES_KUBELET_HOST", expectedKubeletHost)
	t.Setenv("DD_KUBELET_TLS_VERIFY", "true")
	// Workaround to use only env var for the config
	// https://github.com/DataDog/datadog-agent/blob/e7235cf59393e06a187005695e489d63217cab3e/pkg/config/setup/config.go#L2054
	t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "DummyValue")
	if _, err := pkgconfigsetup.LoadWithoutSecret(conf, []string{}); err != nil {
		t.Fatal(err.Error())
	}
	assert.Equal(t, expectedSocketPath, conf.GetString("cri_socket_path"))
	assert.Equal(t, expectedKubeletHost, conf.GetString("kubernetes_kubelet_host"))
	assert.Equal(t, "true", conf.GetString("kubelet_tls_verify"))
}
