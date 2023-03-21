package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/tagger/local"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta"
	"github.com/StackVista/stackstate-process-agent/cmd/agent/features"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/httpclient"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/transactional/transactionbatcher"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/transactional/transactionforwarder"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/transactional/transactionmanager"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/DataDog/datadog-agent/pkg/pidfile"
	log "github.com/cihub/seelog"

	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/tagger"
	"github.com/StackVista/stackstate-process-agent/checks"
	"github.com/StackVista/stackstate-process-agent/config"
)

var opts struct {
	configPath  string
	pidfilePath string
	debug       bool
	version     bool
	check       string
	info        bool
}

// version info sourced from build flags
var (
	Version   string
	GitCommit string
	GitBranch string
	BuildDate string
	GoVersion string
)

// versionString returns the version information filled in at build time
func versionString() string {
	var buf bytes.Buffer

	if Version != "" {
		fmt.Fprintf(&buf, "Version: %s\n", Version)
	}
	if GitCommit != "" {
		fmt.Fprintf(&buf, "Git hash: %s\n", GitCommit)
	}
	if GitBranch != "" {
		fmt.Fprintf(&buf, "Git branch: %s\n", GitBranch)
	}
	if BuildDate != "" {
		fmt.Fprintf(&buf, "Build date: %s\n", BuildDate)
	}
	if GoVersion != "" {
		fmt.Fprintf(&buf, "Go Version: %s\n", GoVersion)
	}

	return buf.String()
}

const (
	agent6DisabledMessage = `process-agent not enabled.
Set env var STS_PROCESS_AGENT_ENABLED=true or add
process_config:
  enabled: "true"
to your stackstate.yaml file.
Exiting.`
)

func runAgent(exit chan bool) {
	if opts.version {
		fmt.Println(versionString())
		os.Exit(0)
	}

	if opts.check == "" && !opts.info && opts.pidfilePath != "" {
		err := pidfile.WritePID(opts.pidfilePath)
		if err != nil {
			log.Errorf("Error while writing PID file, exiting: %v", err)
			os.Exit(1)
		}

		log.Infof("pid '%d' written to pid file '%s'", os.Getpid(), opts.pidfilePath)
		defer func() {
			// remove pidfile if set
			os.Remove(opts.pidfilePath)
		}()
	}

	yamlConf, err := config.NewYamlIfExists(opts.configPath)
	if err != nil {
		log.Criticalf("Error reading stackstate.yaml: %s", err)
		os.Exit(1)
	} else if yamlConf != nil {
		log.Debugf("Setting up agent config for config path: %s", opts.configPath)
		// TODO: Figure out what to do with this
		config.SetupDDAgentConfig(opts.configPath)
	}

	cfg, err := config.NewAgentConfig(yamlConf)
	if err != nil {
		log.Criticalf("Error parsing config: %s", err)
		os.Exit(1)
	}
	err = initInfo(cfg)
	if err != nil {
		log.Criticalf("Error initializing info: %s", err)
		os.Exit(1)
	}

	// Setting up the tagger (must be done after config is setup)
	store := workloadmeta.CreateGlobalStore(workloadmeta.NodeAgentCatalog)
	store.Start(context.TODO())

	tagger.SetDefaultTagger(local.NewTagger(store))
	err = tagger.Init(context.TODO())
	if err != nil {
		log.Errorf("failed to start the tagger: %s", err)
	}
	defer tagger.Stop() //nolint:errcheck

	client := httpclient.NewStackStateClient(makeClientHost(cfg))
	manager := transactionmanager.NewTransactionManager(
		cfg.TxManagerChannelBufferSize,
		cfg.TxManagerTickerIntervalSeconds,
		cfg.TxManagerTimeoutDurationSeconds,
		cfg.TxManagerEvictionDurationSeconds)
	fwd := transactionforwarder.NewTransactionalForwarder(client, manager)
	batcher := transactionbatcher.NewTransactionalBatcher(
		cfg.HostName, cfg.BatcherMaxBufferSize, fwd, manager, cfg.BatcherLogPayloads)

	// Exit if agent is not enabled and we're not debugging a check.
	if !cfg.Enabled && opts.check == "" {
		if yamlConf != nil {
			log.Infof(agent6DisabledMessage)
		}

		// a sleep is necessary to ensure that supervisor registers this process as "STARTED"
		// If the exit is "too quick", we enter a BACKOFF->FATAL loop even though this is an expected exit
		// http://supervisord.org/subprocess.html#process-states
		time.Sleep(5 * time.Second)
		return
	}

	// update docker socket path in info
	dockerSock, err := util.GetDockerSocketPath()
	if err != nil {
		log.Debugf("Docker is not available on this host")
	}
	// we shouldn't quit because docker is not required. If no docker docket is available,
	// we just pass down empty string
	updateDockerSocket(dockerSock)

	log.Debug("Running process-agent with DEBUG logging enabled")
	if opts.check != "" {
		err := debugCheckResults(cfg, opts.check)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		} else {
			os.Exit(0)
		}
		return
	}

	if opts.info {
		// using the debug port to get info to work
		url := "http://localhost:6062/debug/vars"
		if err := Info(os.Stdout, cfg, url); err != nil {
			os.Exit(1)
		}
		return
	}

	// Run a profile server.
	go func() {
		http.ListenAndServe("localhost:6062", nil)
	}()

	// Run metrics server
	go func() {
		promServerMux := http.NewServeMux()
		promServerMux.Handle("/metrics", promhttp.Handler())
		log.Infof("Starting metrics server at http://localhost:6063/metrics")
		http.ListenAndServe("localhost:6063", promServerMux)
	}()

	cl, err := NewCollector(cfg, client, batcher)
	if err != nil {
		log.Criticalf("Error creating collector: %s", err)
		os.Exit(1)
		return
	}
	cl.run(exit)
	for range exit {
		batcher.Stop()
		fwd.Stop()
		manager.Stop()
	}
}

func makeClientHost(cfg *config.AgentConfig) *httpclient.ClientHost {
	host := &httpclient.ClientHost{
		HostURL:           cfg.APIEndpoints[0].Endpoint.String(),
		APIKey:            cfg.APIEndpoints[0].APIKey,
		ContentEncoding:   httpclient.NewGzipContentEncoding(gzip.BestCompression),
		SkipSSLValidation: cfg.SkipSSLValidation,
		RetryWaitMin:      httpclient.DefaultRetryMin,
		RetryWaitMax:      httpclient.DefaultRetryMax,
		NoProxy:           true,
	}

	if cfg.APIEndpoints[0].Endpoint.Scheme == "https" {
		if cfg.HttpsProxy != nil {
			host.ProxyURL = cfg.HttpsProxy
			host.NoProxy = false
		}
	} else {
		if cfg.HttpProxy != nil {
			host.ProxyURL = cfg.HttpProxy
			host.NoProxy = false
		}
	}

	return host
}

func debugCheckResults(cfg *config.AgentConfig, check string) error {
	sysInfo, err := checks.CollectSystemInfo(cfg)
	if err != nil {
		return err
	}

	if check == checks.Connections.Name() {
		// Connections check requires process-check to have occurred first (for process creation ts)
		checks.Process.Init(cfg, sysInfo)
		checks.Process.Run(cfg, features.All(), 0, time.Now())
	}

	names := make([]string, 0, len(checks.All))
	for _, ch := range checks.All {
		if ch.Name() == check {
			ch.Init(cfg, sysInfo)
			return printResults(cfg, ch)
		}
		names = append(names, ch.Name())
	}
	return fmt.Errorf("invalid check '%s', choose from: %v", check, names)
}

func printResults(cfg *config.AgentConfig, ch checks.Check) error {
	// Run the check once to prime the cache.
	if _, err := ch.Run(cfg, features.All(), 0, time.Now()); err != nil {
		return fmt.Errorf("collection error: %s", err)
	}

	if cfg.EnableLocalNetworkTracer && ch.Name() == checks.Connections.Name() {
		fmt.Printf("Waiting 5 seconds to allow for active connections to transmit data\n")
		time.Sleep(5 * time.Second)
	} else {
		time.Sleep(1 * time.Second)
	}

	fmt.Printf("-----------------------------\n\n")
	fmt.Printf("\nResults for check %v\n", ch)
	fmt.Printf("-----------------------------\n\n")

	result, err := ch.Run(cfg, features.All(), 1, time.Now())
	if err != nil {
		return fmt.Errorf("collection error: %s", err)
	}

	for _, m := range result.CollectorMessages {
		b, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal error: %s", err)
		}
		fmt.Println(string(b))
	}
	for _, m := range result.Metrics {
		b, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal error: %s", err)
		}
		fmt.Println(string(b))
	}
	return nil
}
