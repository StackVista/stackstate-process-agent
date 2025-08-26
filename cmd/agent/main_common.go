package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

	localtagger "github.com/DataDog/datadog-agent/comp/core/tagger/impl"
	taggerTelemetry "github.com/DataDog/datadog-agent/comp/core/tagger/telemetry"
	"github.com/DataDog/datadog-agent/comp/core/telemetry/telemetryimpl"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/impl"
	"github.com/DataDog/datadog-agent/pkg/pidfile"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	containers "github.com/DataDog/datadog-agent/pkg/process/util/containers"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/pkg/debug"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/httpclient"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/transactional/transactionbatcher"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/transactional/transactionforwarder"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/transactional/transactionmanager"
	log "github.com/cihub/seelog"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var opts struct {
	configPath  string
	pidfilePath string
	debug       bool
	version     bool
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

	if !opts.info && opts.pidfilePath != "" {
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

	// Setup config for the datadog agent
	ddConfig, err := config.SetupDDAgentConfig(cfg)
	if err != nil {
		log.Criticalf("Error setting up datadog agent config: %s", err)
		os.Exit(1)
	}

	// Configuring hostname after datadog is configured, because it uses datadog logic
	config.ConfigureHostname(cfg)

	// Setting up the workload meta and tagger for the sharedContainerProvider
	wm := workloadmeta.StartWorkloadMetaNoFx(context.TODO(), log.Current)
	tagger, _ := localtagger.NewLocalTagger(ddConfig, wm, taggerTelemetry.NewStore(telemetryimpl.GetCompatComponent()))
	tagger.Start(context.TODO())
	defer tagger.Stop() //nolint:errcheck
	_ = containers.InitSharedContainerProvider(wm, tagger)

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
	if !cfg.Enabled {
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
	// we shouldn't quit because docker is not required. If no docker socket is available,
	// we just pass down empty string
	updateDockerSocket(dockerSock)

	log.Debug("Running process-agent with DEBUG logging enabled")

	if opts.info {
		// using the debug port to get info to work
		url := "http://localhost:6062/debug/vars"
		if err := Info(os.Stdout, cfg, url); err != nil {
			os.Exit(1)
		}
		return
	}

	go func() {
		runMemWatcher()
	}()

	// Run a profile server.
	go func() {
		http.ListenAndServe("localhost:6062", nil)
	}()

	// Run throttle detector
	closeThrottle := debug.DetectThrottle(60*time.Second, 30*time.Second)
	defer closeThrottle()

	// Run metrics server
	go func() {
		promServerMux := http.NewServeMux()
		promServerMux.Handle("/metrics", promhttp.Handler())
		log.Infof("Starting metrics server at http://localhost:6063/metrics")
		http.ListenAndServe("localhost:6063", promServerMux)
	}()

	cl, err := NewCollector(cfg, client, batcher, manager)
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
		if cfg.HTTPSProxy != nil {
			host.ProxyURL = cfg.HTTPSProxy
			host.NoProxy = false
		}
	} else {
		if cfg.HTTPProxy != nil {
			host.ProxyURL = cfg.HTTPProxy
			host.NoProxy = false
		}
	}

	return host
}
