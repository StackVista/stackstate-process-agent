package config

/**
* This file contains all interaction with the datadog dependency configuration. DataDog configuration is making use of
* globals, so this is what we try to smooth out here.
 */
import (
	"fmt"
	ddconfig "github.com/DataDog/datadog-agent/pkg/config"
	"os"
	"strconv"
)

// SetupDDAgentConfig initializes the datadog-agent config with a YAML file.
// This is required for configuration to be available for container listeners.
func SetupDDAgentConfig(cfg *AgentConfig) error {

	if cfg.CriSocketPath != "" {
		os.Setenv("DD_CRI_SOCKET_PATH", cfg.CriSocketPath)
	}

	os.Setenv("DD_KUBERNETES_KUBELET_HOST", cfg.KubernetesKubeletHost)
	os.Setenv("DD_KUBELET_TLS_VERIFY", strconv.FormatBool(cfg.SkipKubeletTLSVerify))

	// load the configuration, this basically initializes everything with defaults
	if _, err := ddconfig.Load(); err != nil {
		return fmt.Errorf("unable to load Datadog config file: %s", err)
	}

	ddconfig.DetectFeatures()

	return nil
}
