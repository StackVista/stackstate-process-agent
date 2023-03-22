package config

/**
* This file contains all interaction with the datadog dependency configuration. DataDog configuration is making use of
* globals, so this is what we try to smooth out here.
 */
import (
	"fmt"
	ddconfig "github.com/DataDog/datadog-agent/pkg/config"
)

// SetupDDAgentConfig initializes the datadog-agent config with a YAML file.
// This is required for configuration to be available for container listeners.
func SetupDDAgentConfig(cfg *AgentConfig) error {
	//ddconfig.Datadog.AddConfigPath(configPath)
	//// If they set a config file directly, let's try to honor that
	//if strings.HasSuffix(configPath, ".yaml") {
	//	ddconfig.Datadog.SetConfigFile(configPath)
	//}

	// load the configuration
	if _, err := ddconfig.Load(); err != nil {
		return fmt.Errorf("unable to load Datadog config file: %s", err)
	}

	ddconfig.DetectFeatures()

	return nil
}
