package forwarder

import (
	"github.com/DataDog/datadog-agent/cmd/agent/common"
	"github.com/DataDog/datadog-agent/pkg/forwarder"
	orchcfg "github.com/DataDog/datadog-agent/pkg/orchestrator/config"
	"github.com/DataDog/datadog-agent/pkg/util/flavor"
	"github.com/StackVista/stackstate-process-agent/config"
	agentConfig "github.com/StackVista/stackstate-process-agent/pkg/config"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/transactional/transactionbatcher"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/transactional/transactionforwarder"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/transactional/transactionmanager"
	log "github.com/cihub/seelog"
)

// ProcessForwarder is a wrapper around the forwarder with the configuration of the process agent
type ProcessForwarder struct {
	forwarder.Forwarder
	*config.AgentConfig
}

// MakeProcessForwarder returns a pointer to a Process Forwarder instance
func MakeProcessForwarder(cfg *config.AgentConfig) *ProcessForwarder {
	// set the common.Forwarder for the internals to work.
	common.Forwarder = forwarder.NewDefaultForwarder(forwarder.NewOptions(extractEndpoints(cfg.APIEndpoints)))
	return &ProcessForwarder{common.Forwarder, cfg}
}

// Start begins running the forwarder
func (pf ProcessForwarder) Start() {
	log.Debugf("Starting forwarder")
	pf.Forwarder.Start() //nolint:errcheck
	log.Debugf("Forwarder started")

	// setup the orchestrator forwarder
	orchestratorForwarder := orchcfg.NewOrchestratorForwarder()
	if orchestratorForwarder != nil {
		orchestratorForwarder.Start() //nolint:errcheck
	}

	transactionforwarder.InitTransactionalForwarder()
	transactionbatcher.InitTransactionalBatcher(pf.AgentConfig.HostName, "agent", agentConfig.GetMaxCapacity(), false)
	txChannelBufferSize, txTimeoutDuration, txEvictionDuration, txTickerInterval := config.GetTxManagerConfig()
	transactionmanager.InitTransactionManager(txChannelBufferSize, txTickerInterval, txTimeoutDuration, txEvictionDuration)

}

// Stop stops the running forwarder, and clears the common.Forwarder global var.
func (pf ProcessForwarder) Stop() {
	log.Debugf("Starting forwarder")
	transactionbatcher.Stop()
	log.Debugf("Forwarder started")
}

func init() {
	// set the flavor to the Process Agent
	flavor.SetFlavor("process_agent")

}

// extractEndpoints creates the keys per domain map for the forwarder.
func extractEndpoints(endpoints []config.APIEndpoint) map[string][]string {
	// setup the forwarder, set up domain -> [apiKeys] from config endpoints
	keysPerDomain := make(map[string][]string)
	for _, apiEndpoint := range endpoints {
		endpoint := apiEndpoint.Endpoint.String()
		if apiKeys, ok := keysPerDomain[endpoint]; ok {
			keysPerDomain[endpoint] = append(apiKeys, apiEndpoint.APIKey)
		} else {
			keysPerDomain[endpoint] = []string{apiEndpoint.APIKey}
		}
	}
	return keysPerDomain
}
