package config

/**
* This file contains all interaction with the datadog dependency configuration. DataDog configuration is making use of
* globals, so this is what we try to smooth out here.
 */
import (
	"fmt"
	"os"
	"strconv"
	"strings"

	modelconfig "github.com/DataDog/datadog-agent/pkg/config/model"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
)

// SetupDDAgentConfig initializes the datadog-agent config with a YAML file.
// This is required for configuration to be available for container listeners.
func SetupDDAgentConfig(cfg *AgentConfig) (modelconfig.Config, error) {
	if cfg.CriSocketPath != "" {
		os.Setenv("DD_CRI_SOCKET_PATH", cfg.CriSocketPath)
	}

	os.Setenv("DD_KUBERNETES_KUBELET_HOST", cfg.KubernetesKubeletHost)
	os.Setenv("DD_KUBELET_TLS_VERIFY", strconv.FormatBool(!cfg.SkipKubeletTLSVerify))
	// Workaround to use only env var for the config
	// https://github.com/DataDog/datadog-agent/blob/e7235cf59393e06a187005695e489d63217cab3e/pkg/config/setup/config.go#L2054
	os.Setenv("AWS_LAMBDA_FUNCTION_NAME", "DummyValue")

	// The real reason why we are loading the config here is to detect the container runtimes (see DetectFeatures method inside `LoadWithoutSecret`)
	config := modelconfig.NewConfig("sts", "DD", strings.NewReplacer(".", "_"))
	pkgconfigsetup.InitConfig(config)
	if _, err := pkgconfigsetup.LoadWithoutSecret(config, nil); err != nil {
		return nil, fmt.Errorf("unable to load Datadog config file: %s", err)
	}
	return config, nil
}
