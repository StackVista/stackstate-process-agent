package config

import (
	ddconfig "github.com/StackVista/stackstate-agent/pkg/config"
	"os"
	"strings"
)

// Datadog is the global configuration object
var Datadog ddconfig.Config

// MainAgentConfig is the global configuration object for main agent internals
var MainAgentConfig ddconfig.Config

func init() {
	// Set the environment prefix to STS. This is used for any code that is "inherited" from the main agent where no
	// branding is applied. eg, The forwarder uses the config in the main agent repo where no branding has been applied.
	MainAgentConfig = ddconfig.Datadog
	MainAgentConfig.SetEnvPrefix("STS")

	// Configure Datadog global configuration. This is used for the config that is used in the process-agent.
	Datadog = ddconfig.NewConfig("stackstate", "STS", strings.NewReplacer(".", "_"))
	// Configuration defaults
	ddconfig.InitConfig(Datadog)
}

// IsContainerized returns whether the Agent is running on a Docker container
func IsContainerized() bool {
	return os.Getenv("DOCKER_STS_AGENT") != ""
}

// GetMainEndpoint returns the main DD URL defined in the config, based on `site` and the prefix, or ddURLKey
func GetMainEndpoint(prefix string, ddURLKey string) string {
	return ddconfig.GetMainEndpointWithConfig(Datadog, prefix, ddURLKey)
}

// Load reads configs files and initializes the config module
func Load() (*ddconfig.Warnings, error) {
	return ddconfig.LoadStackstate(Datadog)
}

// GetMaxCapacity returns the maximum amount of elements per batch for the transactionbatcher
func GetMaxCapacity() int {
	if Datadog.IsSet("batcher_capacity") {
		return Datadog.GetInt("batcher_capacity")
	}

	return ddconfig.DefaultBatcherBufferSize
}
