package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	log "github.com/cihub/seelog"
	"gopkg.in/yaml.v2"

	"github.com/DataDog/datadog-agent/pkg/process/util"
)

// YamlAgentConfig is a structure used for marshaling the datadog.yaml configuration
// available in Agent versions >= 6
type YamlAgentConfig struct {
	APIKey            string `yaml:"api_key"`
	Site              string `yaml:"site"`
	StsURL            string `yaml:"sts_url"`
	SkipSSLValidation bool   `yaml:"skip_ssl_validation"`
	KubeletTlsVerify  bool   `yaml:"kubelet_tls_verify"`
	// Whether the process-agent should output logs to console
	LogToConsole bool   `yaml:"log_to_console"`
	LogLevel     string `yaml:"log_level"`
	// Incremental publishing: send only changes to server, instead of snapshots
	IncrementalPublishingEnabled string `yaml:"incremental_publishing_enabled"`
	// Periodically resend all data to allow downstream to recover from any lost data
	IncrementalPublishingRefreshInterval int `yaml:"incremental_publishing_refresh_interval"`
	// Process-specific configuration
	Process struct {
		// A string indicate the enabled state of the Agent.
		// If "false" (the default) we will only collect containers.
		// If "true" we will collect containers and processes.
		// If "disabled" the agent will be disabled altogether and won't start.
		Enabled string `yaml:"enabled"`
		// The full path to the file where process-agent logs will be written.
		LogFile string `yaml:"log_file"`
		// The interval, in seconds, at which we will run each check. If you want consistent
		// behavior between real-time you may set the Container/ProcessRT intervals to 10.
		// Defaults to 10s for normal checks and 2s for others.
		Intervals struct {
			Container         int `yaml:"container"`
			ContainerRealTime int `yaml:"container_realtime"`
			Process           int `yaml:"process"`
			ProcessRealTime   int `yaml:"process_realtime"`
			Connections       int `yaml:"connections"`
		} `yaml:"intervals"`
		// The expiration time in, in minutes, that is used to evict items from the network relation cache
		NetworkRelationCacheDurationMin int `yaml:"network_relation_cache_duration_min"`
		// The expiration time in, in minutes, that is used to evict items from the process cache
		ProcessCacheDurationMin int `yaml:"process_cache_duration_min"`
		// The filters are used to excluded processes based on some value
		Filters struct {
			// The ShortLivedNetworkRelations filter determines whether a network relation is considered "shortlived" and filters it based on the
			// configured qualifier seconds
			ShortLivedNetworkRelations struct {
				Enabled       string `yaml:"enabled"`
				QualifierSecs int    `yaml:"qualifier_secs"`
			} `yaml:"short_lived_network_relations"`
			// The ShortLived filter determines whether a process is considered "shortlived" and filters it based on the
			// configured qualifier seconds
			ShortLivedProcesses struct {
				Enabled       string `yaml:"enabled"`
				QualifierSecs int    `yaml:"qualifier_secs"`
			} `yaml:"short_lived_processes"`
		} `yaml:"filters"`
		// The inclusion amounts for the top resource consuming processes. These processes will be included regardless
		// of being included in the blacklist patterns.
		// TODO: Move to Filters
		Blacklist struct {
			Inclusions struct {
				AmountTopCPUPercentageUsage int `yaml:"amount_top_cpu_pct_usage"`
				CPUPercentageUsageThreshold int `yaml:"cpu_pct_usage_threshold"`
				AmountTopIOReadUsage        int `yaml:"amount_top_io_read_usage"`
				AmountTopIOWriteUsage       int `yaml:"amount_top_io_write_usage"`
				AmountTopMemoryUsage        int `yaml:"amount_top_mem_usage"`
				MemoryUsageThreshold        int `yaml:"mem_usage_threshold"`
			} `yaml:"inclusions"`
			// A list of regex patterns that will exclude a process if matched.
			Patterns []string `yaml:"patterns"`
		} `yaml:"process_blacklist"`
		// Enable/Disable the DataScrubber to obfuscate process args
		// XXX: Using a bool pointer to differentiate between empty and set.
		ScrubArgs *bool `yaml:"scrub_args,omitempty"`
		// A custom word list to enhance the default one used by the DataScrubber
		CustomSensitiveWords []string `yaml:"custom_sensitive_words"`
		// Strips all process arguments
		StripProcessArguments bool `yaml:"strip_proc_arguments"`
		// How many check results to buffer in memory when POST fails. The default is usually fine.
		QueueSize int `yaml:"queue_size"`
		// The maximum number of file descriptors to open when collecting net connections.
		// Only change if you are running out of file descriptors from the Agent.
		MaxProcFDs int `yaml:"max_proc_fds"`
		// The maximum number of processes or containers per message.
		// Only change if the defaults are causing issues.
		MaxPerMessage int `yaml:"max_per_message"`
		// The maximum number of connections per message.
		// Only change if the defaults are causing issues.
		MaxConnectionsPerMessage int `yaml:"max_connections_per_message"`
		// Overrides the path to the Agent bin used for getting the hostname. The default is usually fine.
		DDAgentBin string `yaml:"sts_agent_bin"`
		// Overrides of the environment we pass to fetch the hostname. The default is usually fine.
		DDAgentEnv []string `yaml:"sts_agent_env"`
		// Optional additional pairs of endpoint_url => []apiKeys to submit to other locations.
		AdditionalEndpoints map[string][]string `yaml:"additional_endpoints"`
		// Windows-specific configuration goes in this section.
		Windows struct {
			// Sets windows process table refresh rate (in number of check runs)
			ArgsRefreshInterval int `yaml:"args_refresh_interval"`
			// Controls getting process arguments immediately when a new process is discovered
			// XXX: Using a bool pointer to differentiate between empty and set.
			AddNewArgs *bool `yaml:"add_new_args,omitempty"`
		} `yaml:"windows"`
	} `yaml:"process_config"`
	// Network-tracing specific configuration
	Network struct {
		// A string indicating the enabled state of the network tracer.
		NetworkTracingEnabled string `yaml:"network_tracing_enabled"`
		// A string indicating whether we use /proc to get the initial connections
		NetworkInitialConnectionFromProc string `yaml:"initial_connections_from_proc"`
		// The full path to the location of the unix socket where network traces will be accessed
		UnixSocketPath string `yaml:"nettracer_socket"`
		// The full path to the file where network-tracer logs will be written.
		LogFile string `yaml:"log_file"`
		// The maximum number of in flight connections the network tracer keeps track of
		NetworkMaxConnections int `yaml:"max_connections"`
		// An integer indicating the amount of seconds for the retry interval for initializing the network tracer.
		NetworkTracerInitRetryDuration int `yaml:"network_tracer_retry_init_duration_sec"`
		// An integer indicating the amount of retries to use for initializing the network tracer.
		NetworkTracerInitRetryAmount int `yaml:"network_tracer_retry_init_amount"`
		// Whenever debugging statements of eBPF code of network tracer should be redirected to the agent log
		EBPFDebuglogEnabled string `yaml:"ebpf_debuglog_enabled"`
		// Location of the ebpf code
		EBPFArtifactDir string `yaml:"ebpf_artifact_dir"`
		// A string indicating the enabled state of the protocol inspection.
		ProtocolInspectionEnabled string `yaml:"protocol_inspection_enabled"`
		HTTPMetrics               struct {
			// Specifies which algorithm to use to collapse measurements: collapsing_lowest_dense, collapsing_highest_dense, unbounded
			SketchType string `yaml:"sketch_type"`
			// A maximum number of bins of the ddSketch we use to store percentiles
			MaxNumBins int `yaml:"max_num_bins"`
			// Desired accuracy for computed percentiles. 0.01 means, for example, we can say that p99 is 100ms +- 1ms
			Accuracy float64 `yaml:"accuracy"`
		} `yaml:"http_metrics"`
	} `yaml:"network_tracer_config"`
	TransactionManager struct {
		// ChannelBufferSize is the concurrent transactions before the tx manager begins backpressure
		ChannelBufferSize int `yaml:"channel_buffer_size"`
		// TimeoutDurationSeconds is the amount of time before a transaction is marked as stale, 5 minutes by default
		TimeoutDurationSeconds int `yaml:"timeout_duration_seconds"`
		// EvictionDurationSeconds is the amount of time before a transaction is evicted and rolled back, 10 minutes by default
		EvictionDurationSeconds int `yaml:"eviction_duration_seconds"`
		// TickerIntervalSeconds is the ticker interval to mark transactions as stale / timeout.
		TickerDurationSeconds int `yaml:"ticket_duration_seconds"`
	} `yaml:"transaction_manager"`
	Batcher struct {
		// Amount of data buffered in the batcher
		MaxBufferSize int  `yaml:"max_buffer_size"`
		LogPayloads   bool `yaml:"log_payloads"`
	} `yaml:"batcher"`
	Kubernetes struct {
		KubeletHost string `yaml:"kubelet_host"`
	} `yaml:"kubernetes"`
	Containers struct {
		CriSocketPath string `yaml:"cri_socket_path"`
	} `yaml:"containers"`
	Proxy struct {
		HTTPS string `yaml:"https"`
		HTTP  string `yaml:"http"`
	} `yaml:"proxy"`
}

// NewYamlIfExists returns a new YamlAgentConfig if the given configPath is exists.
func NewYamlIfExists(configPath string) (*YamlAgentConfig, error) {
	var yamlConf YamlAgentConfig

	// Set default values for booleans otherwise it will default to false.
	defaultScrubArgs := true
	yamlConf.Process.ScrubArgs = &defaultScrubArgs
	defaultNewArgs := true
	yamlConf.Process.Windows.AddNewArgs = &defaultNewArgs

	if util.PathExists(configPath) {
		lines, err := util.ReadLines(configPath)
		if err != nil {
			return nil, fmt.Errorf("read error: %s", err)
		}
		if err = yaml.Unmarshal([]byte(strings.Join(lines, "\n")), &yamlConf); err != nil {
			return nil, fmt.Errorf("parse error: %s", err)
		}
		return &yamlConf, nil
	}
	return nil, nil
}

func mergeYamlConfig(agentConf *AgentConfig, yc *YamlAgentConfig) (*AgentConfig, error) {
	var err error

	agentConf.APIEndpoints[0].APIKey = yc.APIKey

	if enabled, err := isAffirmative(yc.Process.Enabled); enabled {
		agentConf.Enabled = true
		agentConf.EnabledChecks = processChecks
	} else if strings.ToLower(yc.Process.Enabled) == "disabled" {
		agentConf.Enabled = false
	} else if !enabled && err == nil {
		agentConf.Enabled = true
		agentConf.EnabledChecks = processChecks // sts
	}

	if yc.LogToConsole {
		agentConf.LogToConsole = true
	}
	if yc.Process.LogFile != "" {
		agentConf.LogFile = yc.Process.LogFile
	}
	if yc.LogLevel != "" {
		agentConf.LogLevel = yc.LogLevel
	}

	// (Re)configure the logging from our configuration
	if err := NewLoggerLevel(agentConf.LogLevel, agentConf.LogFile, agentConf.LogToConsole); err != nil {
		return nil, err
	}

	if yc.StsURL != "" {
		defaultURL, err := url.Parse(yc.StsURL)
		if err == nil {
			agentConf.APIEndpoints[0].Endpoint = defaultURL
		}
		log.Infof("Setting process api endpoint from config using `sts_url`: %s", defaultURL)
	}

	if enabled, err := isAffirmative(yc.IncrementalPublishingEnabled); err == nil {
		log.Infof("Overriding incremental publishing with %ds", yc.IncrementalPublishingEnabled)
		agentConf.EnableIncrementalPublishing = enabled
	} else {
		agentConf.EnableIncrementalPublishing = true
	}
	if yc.IncrementalPublishingRefreshInterval != 0 {
		log.Infof("Overriding incremental publishing interval with %ds", yc.IncrementalPublishingRefreshInterval)
		agentConf.IncrementalPublishingRefreshInterval = time.Duration(yc.IncrementalPublishingRefreshInterval) * time.Second
	}
	if yc.Process.Intervals.Container != 0 {
		log.Infof("Overriding container check interval to %ds", yc.Process.Intervals.Container)
		agentConf.CheckIntervals["container"] = time.Duration(yc.Process.Intervals.Container) * time.Second
	}
	if yc.Process.Intervals.ContainerRealTime != 0 {
		log.Infof("Overriding real-time container check interval to %ds", yc.Process.Intervals.ContainerRealTime)
		agentConf.CheckIntervals["rtcontainer"] = time.Duration(yc.Process.Intervals.ContainerRealTime) * time.Second
	}
	if yc.Process.Intervals.Process != 0 {
		log.Infof("Overriding process check interval to %ds", yc.Process.Intervals.Process)
		agentConf.CheckIntervals["process"] = time.Duration(yc.Process.Intervals.Process) * time.Second
	}
	if yc.Process.Intervals.ProcessRealTime != 0 {
		log.Infof("Overriding real-time process check interval to %ds", yc.Process.Intervals.ProcessRealTime)
		agentConf.CheckIntervals["rtprocess"] = time.Duration(yc.Process.Intervals.Process) * time.Second
	}
	if yc.Process.Intervals.Connections != 0 {
		log.Infof("Overriding connections check interval to %ds", yc.Process.Intervals.Connections)
		agentConf.CheckIntervals["connections"] = time.Duration(yc.Process.Intervals.Connections) * time.Second
	}

	setProcessBlacklist(agentConf,
		yc.Process.Blacklist.Patterns,
		yc.Process.Blacklist.Inclusions.AmountTopCPUPercentageUsage,
		yc.Process.Blacklist.Inclusions.AmountTopIOReadUsage, yc.Process.Blacklist.Inclusions.AmountTopIOWriteUsage,
		yc.Process.Blacklist.Inclusions.AmountTopMemoryUsage,
		yc.Process.Blacklist.Inclusions.CPUPercentageUsageThreshold, yc.Process.Blacklist.Inclusions.MemoryUsageThreshold)

	if enabled, err := isAffirmative(yc.Process.Filters.ShortLivedProcesses.Enabled); err == nil {
		setProcessFilters(agentConf, enabled, yc.Process.Filters.ShortLivedProcesses.QualifierSecs)
	}

	if enabled, err := isAffirmative(yc.Process.Filters.ShortLivedNetworkRelations.Enabled); err == nil {
		setNetworkRelationFilters(agentConf, enabled, yc.Process.Filters.ShortLivedNetworkRelations.QualifierSecs)
	}

	if yc.Process.ProcessCacheDurationMin > 0 {
		agentConf.ProcessCacheDurationMin = time.Duration(yc.Process.ProcessCacheDurationMin) * time.Minute
	}

	if yc.Process.NetworkRelationCacheDurationMin > 0 {
		agentConf.NetworkRelationCacheDurationMin = time.Duration(yc.Process.NetworkRelationCacheDurationMin) * time.Minute
	}

	if yc.Network.NetworkTracerInitRetryDuration > 0 {
		agentConf.NetworkTracerInitRetryDuration = time.Duration(yc.Network.NetworkTracerInitRetryDuration) * time.Second
	}

	if yc.Network.NetworkTracerInitRetryAmount > 0 {
		agentConf.NetworkTracerInitRetryAmount = yc.Network.NetworkTracerInitRetryAmount
	}

	// DataScrubber
	if yc.Process.ScrubArgs != nil {
		agentConf.Scrubber.Enabled = *yc.Process.ScrubArgs
	}
	agentConf.Scrubber.AddCustomSensitiveWords(yc.Process.CustomSensitiveWords)
	if yc.Process.StripProcessArguments {
		agentConf.Scrubber.StripAllArguments = yc.Process.StripProcessArguments
	}

	if yc.Process.QueueSize > 0 {
		agentConf.QueueSize = yc.Process.QueueSize
	}
	if yc.Process.MaxProcFDs > 0 {
		agentConf.MaxProcFDs = yc.Process.MaxProcFDs
	}
	if yc.Process.MaxPerMessage > 0 {
		if yc.Process.MaxPerMessage <= maxMessageBatch {
			agentConf.MaxPerMessage = yc.Process.MaxPerMessage
		} else {
			log.Warn("Overriding the configured item count per message limit because it exceeds maximum")
		}
	}
	if yc.Process.MaxConnectionsPerMessage > 0 {
		agentConf.MaxConnectionsPerMessage = yc.Process.MaxConnectionsPerMessage
	}

	if yc.TransactionManager.ChannelBufferSize > 0 {
		agentConf.TxManagerChannelBufferSize = yc.TransactionManager.ChannelBufferSize
	}

	if yc.TransactionManager.EvictionDurationSeconds > 0 {
		agentConf.TxManagerEvictionDurationSeconds = time.Duration(yc.TransactionManager.EvictionDurationSeconds) * time.Second
	}

	if yc.TransactionManager.TimeoutDurationSeconds > 0 {
		agentConf.TxManagerTimeoutDurationSeconds = time.Duration(yc.TransactionManager.TimeoutDurationSeconds) * time.Second
	}

	if yc.TransactionManager.TickerDurationSeconds > 0 {
		agentConf.TxManagerTickerIntervalSeconds = time.Duration(yc.TransactionManager.TickerDurationSeconds) * time.Second
	}

	if yc.Batcher.MaxBufferSize > 0 {
		agentConf.BatcherMaxBufferSize = yc.Batcher.MaxBufferSize
	}

	if yc.Batcher.LogPayloads {
		agentConf.BatcherLogPayloads = yc.Batcher.LogPayloads
	}

	if yc.Proxy.HTTPS != "" {
		agentConf.HTTPSProxy, err = url.Parse(yc.Proxy.HTTPS)
		if err != nil {
			return nil, fmt.Errorf("error parsing proxy.https: %s", err)
		}
	}

	if yc.Proxy.HTTP != "" {
		agentConf.HTTPProxy, err = url.Parse(yc.Proxy.HTTP)
		if err != nil {
			return nil, fmt.Errorf("error parsing proxy.http: %s", err)
		}
	}

	for endpointURL, apiKeys := range yc.Process.AdditionalEndpoints {
		u, err := url.Parse(endpointURL)
		if err != nil {
			return nil, fmt.Errorf("invalid additional endpoint url '%s': %s", endpointURL, err)
		}
		for _, k := range apiKeys {
			agentConf.APIEndpoints = append(agentConf.APIEndpoints, APIEndpoint{
				APIKey:   k,
				Endpoint: u,
			})
		}
	}

	// [STS] set the skip_ssl_validation for the process-agent + main-agent config
	if yc.SkipSSLValidation {
		agentConf.SkipSSLValidation = true
		log.Infof("Setting skip_ssl_validation to: %s", yc.SkipSSLValidation)
	}

	// [STS] set the kubelet_tls_verify for the process-agent + main-agent config
	if yc.KubeletTlsVerify == false {
		agentConf.KubeletTlsVerify = false
		log.Infof("Setting kubelet tls verify to: %s", yc.KubeletTlsVerify)
	}

	if yc.Kubernetes.KubeletHost != "" {
		agentConf.KubernetesKubeletHost = yc.Kubernetes.KubeletHost
	}

	if yc.Containers.CriSocketPath != "" {
		agentConf.CriSocketPath = yc.Containers.CriSocketPath
	}

	return agentConf, nil
}

func mergeNetworkYamlConfig(agentConf *AgentConfig, networkConf *YamlAgentConfig) (*AgentConfig, error) {
	if enabled, _ := isAffirmative(networkConf.Network.NetworkTracingEnabled); enabled {
		agentConf.EnabledChecks = append(agentConf.EnabledChecks, "connections")
		agentConf.EnableNetworkTracing = enabled
	}
	if networkConf.Network.LogFile != "" {
		agentConf.LogFile = networkConf.Network.LogFile
	}
	if enabled, err := isAffirmative(networkConf.Network.EBPFDebuglogEnabled); err == nil {
		agentConf.NetworkTracer.EbpfDebuglogEnabled = enabled
	}
	if protMetrEnabled, err := isAffirmative(networkConf.Network.ProtocolInspectionEnabled); err == nil {
		agentConf.NetworkTracer.EnableProtocolInspection = protMetrEnabled
	}
	if networkConf.Network.NetworkMaxConnections != 0 {
		agentConf.NetworkTracerMaxConnections = networkConf.Network.NetworkMaxConnections
	}
	if networkConf.Network.EBPFArtifactDir != "" {
		agentConf.NetworkTracer.EbpfArtifactDir = networkConf.Network.EBPFArtifactDir
	}
	return agentConf, nil
}
