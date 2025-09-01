//go:generate goderive .

package config

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/hostname"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/transactional/transactionbatcher"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/transactional/transactionmanager"
	"k8s.io/utils/strings/slices"

	log "github.com/cihub/seelog"
)

var (
	processChecks = []string{"process"}

	// List of known Kubernetes images that we want to exclude by default.
	defaultKubeBlacklist = []string{
		"image:gcr.io/google_containers/pause.*",
		"image:openshift/origin-pod",
	}
)

// NetworkTracerConfig contains some[1] of the network tracer configuration options
type NetworkTracerConfig struct {
	// Enables protocol inspection from eBPF code
	EnableProtocolInspection bool
	// Enables protocol inspection from eBPF code
	EnableHTTPSInspection bool
	// Location of the ebpf
	EbpfArtifactDir string
	// Enabling http tracing using x-reqeust-id headers
	EnableHTTPTracing bool
	// ProbeDebugLog logging when loading probe
	ProbeDebugLog bool
	// Max number of http stats buffered
	MaxHTTPStatsBuffered int
	// Max number of http observations buffered
	MaxHTTPObservationsBuffered int
	// Protocols to disable, mostly for debugging
	DisabledProtocols []string
}

// APIEndpoint is a single endpoint where process data will be submitted.
type APIEndpoint struct {
	APIKey   string
	Endpoint *url.URL
}

// AgentConfig is the global config for the process-agent. This information
// is sourced from config files and the environment variables.
type AgentConfig struct {
	HostName                 string
	APIEndpoints             []APIEndpoint
	SkipSSLValidation        bool
	SkipKubeletTLSVerify     bool
	LogFile                  string
	LogLevel                 string
	QueueSize                int
	Blacklist                []*regexp.Regexp
	Scrubber                 *DataScrubber
	MaxProcFDs               int
	MaxPerMessage            int
	MaxConnectionsPerMessage int
	Transport                *http.Transport `json:"-"`
	Logger                   *LoggerConfig

	// Process Cache Expiration, In Minutes
	ProcessCacheDurationMin time.Duration

	// ShortLived process filtering
	EnableShortLivedProcessFilter  bool
	ShortLivedProcessQualifierSecs time.Duration

	// Relation Cache Expiration, In Minutes
	NetworkRelationCacheDurationMin time.Duration

	// ShortLived network relation filtering
	EnableShortLivedNetworkRelationFilter  bool
	ShortLivedNetworkRelationQualifierSecs time.Duration

	// Top resource using process inclusion amounts
	AmountTopCPUPercentageUsage int
	CPUPercentageUsageThreshold int
	AmountTopIOReadUsage        int
	AmountTopIOWriteUsage       int
	AmountTopMemoryUsage        int
	MemoryUsageThreshold        int

	// Kubernetes/Openshift cluster name
	ClusterName string

	// Publishing settings
	EnableIncrementalPublishing          bool          // Reduce downstream load by only publishing incremental changes. Remote should support this
	IncrementalPublishingRefreshInterval time.Duration // Periodically resend all data to allow downstream to recover from any lost data

	// Network collection configuration
	EnableNetworkTracing              bool
	EnableLocalNetworkTracer          bool // To have the network tracer embedded in the process-agent
	NetworkInitialConnectionsFromProc bool
	NetworkTracerSocketPath           string
	NetworkTracerLogFile              string
	NetworkTracerInitRetryDuration    time.Duration
	NetworkTracerInitRetryAmount      int
	NetworkTracer                     *NetworkTracerConfig
	// Maximum connections the network tracer keeps track of
	NetworkTracerMaxConnections int

	// Check config
	EnabledChecks                []string
	CheckIntervals               map[string]time.Duration
	ReportCheckHealthState       bool
	CheckHealthStateMessageLimit int

	// Containers
	CriSocketPath      string
	ContainerBlacklist []string
	ContainerWhitelist []string

	// Transaction Manager
	TxManagerChannelBufferSize       int
	TxManagerTimeoutDurationSeconds  time.Duration
	TxManagerEvictionDurationSeconds time.Duration
	TxManagerTickerIntervalSeconds   time.Duration

	// Batcher
	BatcherMaxBufferSize int
	BatcherLogPayloads   bool

	// Kubernetes
	KubernetesKubeletHost string

	// Proxy
	HTTPSProxy *url.URL
	HTTPProxy  *url.URL

	// Break down HTTP stats by path
	// Careful: The path label can have a very high cardinality
	HTTPStatsPerPath bool

	// True when the agent is runned locally, for debugging purposes
	LocalRun bool
}

// CheckIsEnabled returns a bool indicating if the given check name is enabled.
func (a AgentConfig) CheckIsEnabled(checkName string) bool {
	return slices.Contains(a.EnabledChecks, checkName)
}

// CheckInterval returns the interval for the given check name, defaulting to 10s if not found.
func (a AgentConfig) CheckInterval(checkName string) time.Duration {
	d, ok := a.CheckIntervals[checkName]
	if !ok {
		log.Errorf("missing check interval for '%s', you must set a default", checkName)
		d = 30 * time.Second
	}
	return d
}

const (
	defaultEndpoint = "http://localhost:7077/stsAgent"
	maxMessageBatch = 100
)

// NewDefaultAgentConfig returns an AgentConfig with defaults initialized
func NewDefaultAgentConfig() *AgentConfig {
	u, err := url.Parse(defaultEndpoint)
	if err != nil {
		// This is a hardcoded URL so parsing it should not fail
		panic(err)
	}

	ac := &AgentConfig{
		APIEndpoints:             []APIEndpoint{{Endpoint: u}},
		SkipSSLValidation:        false,
		SkipKubeletTLSVerify:     false,
		LogFile:                  defaultLogFilePath,
		LogLevel:                 "info",
		QueueSize:                20,
		MaxProcFDs:               200,
		MaxPerMessage:            maxMessageBatch,
		MaxConnectionsPerMessage: 100,
		HostName:                 "",

		Blacklist: deriveFmapConstructRegex(constructRegex, defaultBlacklistPatterns),

		// Top resource using process inclusion amounts
		AmountTopCPUPercentageUsage: 0,
		AmountTopIOReadUsage:        0,
		AmountTopIOWriteUsage:       0,
		AmountTopMemoryUsage:        0,

		EnableIncrementalPublishing:          true,
		IncrementalPublishingRefreshInterval: 1 * time.Minute,

		// Network Relation Cache Expiration duration
		NetworkRelationCacheDurationMin: 5 * time.Minute,

		// ShortLived network relation filtering
		EnableShortLivedNetworkRelationFilter:  true,
		ShortLivedNetworkRelationQualifierSecs: 60 * time.Second,

		// Process Cache Expiration duration
		ProcessCacheDurationMin: 5 * time.Minute,

		// ShortLived process filtering
		EnableShortLivedProcessFilter:  true,
		ShortLivedProcessQualifierSecs: 60 * time.Second,

		// Network collection configuration
		EnableNetworkTracing:           false,
		NetworkTracerMaxConnections:    10000,
		NetworkTracerInitRetryDuration: 5 * time.Second,
		NetworkTracerInitRetryAmount:   3,
		NetworkTracer: &NetworkTracerConfig{
			EnableProtocolInspection:    true,
			EnableHTTPSInspection:       true,
			EbpfArtifactDir:             "/opt/stackstate-agent/ebpf",
			EnableHTTPTracing:           false,
			ProbeDebugLog:               false,
			MaxHTTPStatsBuffered:        100000,
			MaxHTTPObservationsBuffered: 100000,
			DisabledProtocols:           []string{},
		},

		// Check config
		EnabledChecks: processChecks,
		CheckIntervals: map[string]time.Duration{
			"process":     30 * time.Second,
			"connections": 30 * time.Second,
		},
		ReportCheckHealthState:       true,
		CheckHealthStateMessageLimit: 2048,

		// Transaction manager
		TxManagerChannelBufferSize:       transactionmanager.DefaultTxManagerChannelBufferSize,
		TxManagerTimeoutDurationSeconds:  transactionmanager.DefaultTxManagerTimeoutDurationSeconds * time.Second,
		TxManagerEvictionDurationSeconds: transactionmanager.DefaultTxManagerEvictionDurationSeconds * time.Second,
		TxManagerTickerIntervalSeconds:   transactionmanager.DefaultTxManagerTickerIntervalSeconds * time.Second,

		// Batcher
		BatcherMaxBufferSize: transactionbatcher.DefaultBatcherBufferSize,
		BatcherLogPayloads:   false,

		// DataScrubber to hide command line sensitive words
		Scrubber: NewDefaultDataScrubber(),

		// Proxy
		HTTPSProxy: nil,
		HTTPProxy:  nil,

		// Break down HTTP stats by path
		HTTPStatsPerPath: false,
		LocalRun:         false,
	}

	// Set default values for proc/sys paths if unset.
	// Don't set this is /host is not mounted to use context within container.
	// Generally only applicable for container-only cases like Fargate.
	if IsContainerized() && pathExists("/host") {
		if v := os.Getenv("HOST_PROC"); v == "" {
			os.Setenv("HOST_PROC", "/host/proc")
		}
		if v := os.Getenv("HOST_SYS"); v == "" {
			os.Setenv("HOST_SYS", "/host/sys")
		}
	}

	if isRunningInKubernetes() {
		ac.ContainerBlacklist = defaultKubeBlacklist
	}

	return ac
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func isRunningInKubernetes() bool {
	return os.Getenv("KUBERNETES_SERVICE_HOST") != ""
}

// NewAgentConfig returns an AgentConfig using a configuration file. It can be nil
// if there is no file available. In this case we'll configure only via environment.
func NewAgentConfig(agentYaml *YamlAgentConfig) (*AgentConfig, error) {
	var err error
	cfg := NewDefaultAgentConfig()

	if agentYaml != nil {
		if cfg, err = mergeYamlConfig(cfg, agentYaml); err != nil {
			return nil, err
		}
		if cfg, err = mergeNetworkYamlConfig(cfg, agentYaml); err != nil {
			return nil, err
		}
	}

	// Use environment to override any additional config.
	cfg = mergeEnvironmentVariables(cfg)

	// Python-style log level has WARNING vs WARN
	cfg.LogLevel = strings.ToLower(cfg.LogLevel)
	if cfg.LogLevel == "warning" {
		cfg.LogLevel = "warn"
	}

	// (Re)configure the logging from our configuration
	// We always log to stdout
	if err := NewLoggerLevel(cfg.LogLevel, cfg.LogFile, true); err != nil {
		return nil, err
	}

	if len(cfg.APIEndpoints) > 1 {
		log.Warnf("Multiple API endpoints is not supported. Additional endpoints will be ignored")
	}

	if cfg.EnableShortLivedProcessFilter {
		log.Infof("Process ShortLived filter enabled for processes younger than %s",
			cfg.ShortLivedProcessQualifierSecs)
	} else {
		log.Info("Process ShortLived filter disabled")
	}

	if cfg.EnableShortLivedNetworkRelationFilter {
		log.Infof("Relation ShortLived filter enabled for connections that are once off and were observed for "+
			"less than %s seconds", cfg.ShortLivedNetworkRelationQualifierSecs)
	} else {
		log.Infof("Relation ShortLived filter disabled")
	}

	return cfg, nil
}

// mergeEnvironmentVariables applies overrides from environment variables to the process agent configuration
func mergeEnvironmentVariables(c *AgentConfig) *AgentConfig {
	var err error
	if v := os.Getenv("STS_HOSTNAME"); v != "" {
		log.Info("overriding hostname from env DD_HOSTNAME value")
		c.HostName = v
	}

	// Support API_KEY and DD_API_KEY but prefer DD_API_KEY.
	var apiKey string
	if v := os.Getenv("API_KEY"); v != "" {
		apiKey = v
		log.Info("overriding API key from env API_KEY value")
	}
	if v := os.Getenv("STS_API_KEY"); v != "" {
		apiKey = v
		log.Infof("overriding API key from env DD_API_KEY value %s", apiKey)
	}
	if apiKey != "" {
		vals := strings.Split(apiKey, ",")
		for i := range vals {
			vals[i] = strings.TrimSpace(vals[i])
		}
		c.APIEndpoints[0].APIKey = vals[0]
	}

	if v := os.Getenv("STS_LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}

	if proxyURL := os.Getenv("HTTPS_PROXY"); proxyURL != "" {
		c.HTTPSProxy, err = url.Parse(proxyURL)
		if err != nil {
			log.Errorf("error parsing HTTPS_PROXY, not using a proxy: %s", err)
		}
	}

	if proxyURL := os.Getenv("STS_HTTPS_PROXY"); proxyURL != "" {
		c.HTTPSProxy, err = url.Parse(proxyURL)
		if err != nil {
			log.Errorf("error parsing STS_HTTPS_PROXY, not using a proxy: %s", err)
		}
	}

	if proxyURL := os.Getenv("STS_PROXY_HTTPS"); proxyURL != "" {
		c.HTTPSProxy, err = url.Parse(proxyURL)
		if err != nil {
			log.Errorf("error parsing STS_PROXY_HTTPS, not using a proxy: %s", err)
		}
	}

	if proxyURL := os.Getenv("HTTP_PROXY"); proxyURL != "" {
		c.HTTPProxy, err = url.Parse(proxyURL)
		if err != nil {
			log.Errorf("error parsing HTTP_PROXY, not using a proxy: %s", err)
		}
	}

	if proxyURL := os.Getenv("STS_HTTP_PROXY"); proxyURL != "" {
		c.HTTPProxy, err = url.Parse(proxyURL)
		if err != nil {
			log.Errorf("error parsing STS_HTTP_PROXY, not using a proxy: %s", err)
		}
	}

	if proxyURL := os.Getenv("STS_PROXY_HTTP"); proxyURL != "" {
		c.HTTPProxy, err = url.Parse(proxyURL)
		if err != nil {
			log.Errorf("error parsing STS_PROXY_HTTP, not using a proxy: %s", err)
		}
	}

	// STS
	if v := os.Getenv("STS_PROCESS_AGENT_URL"); v != "" {
		u, err := url.Parse(v)
		if err != nil {
			log.Warnf("STS_PROCESS_AGENT_URL is invalid: %s", err)
		} else {
			log.Infof("overriding API endpoint from env")
			c.APIEndpoints[0].Endpoint = u
		}
		log.Infof("Overriding process api endpoint with environment variable `STS_PROCESS_AGENT_URL`: %s", u)
	}

	// Process Arguments Scrubbing
	if enabled, err := isAffirmative(os.Getenv("STS_SCRUB_ARGS")); enabled {
		c.Scrubber.Enabled = true
	} else if !enabled && err == nil {
		c.Scrubber.Enabled = false
	}

	if v := os.Getenv("STS_CUSTOM_SENSITIVE_WORDS"); v != "" {
		c.Scrubber.AddCustomSensitiveWords(strings.Split(v, ","))
	}
	if ok, _ := isAffirmative(os.Getenv("STS_STRIP_PROCESS_ARGS")); ok {
		c.Scrubber.StripAllArguments = true
	}

	// Docker config
	if v := os.Getenv("STS_CONTAINER_BLACKLIST"); v != "" {
		c.ContainerBlacklist = strings.Split(v, ",")
	}
	if v := os.Getenv("STS_CONTAINER_WHITELIST"); v != "" {
		c.ContainerWhitelist = strings.Split(v, ",")
	}

	// Note: this feature is in development and should not be used in production environments
	// STS: ignore DD notes, this will enable our tcptracer-ebpf and that is production ready
	if ok, _ := isAffirmative(os.Getenv("STS_NETWORK_TRACING_ENABLED")); ok {
		c.EnabledChecks = append(c.EnabledChecks, "connections")
		c.EnableNetworkTracing = ok
	}
	if v := os.Getenv("STS_NETTRACER_EBPF_ARTIFACTS_DIR"); v != "" {
		c.NetworkTracer.EbpfArtifactDir = v
	}

	if ok, _ := isAffirmative(os.Getenv("STS_INCREMENTAL_PUBLISHING")); ok {
		c.EnableIncrementalPublishing = ok
	}

	if ok, err := isAffirmative(os.Getenv("STS_PROCESS_AGENT_REPORT_HEALTH_STATE")); err == nil {
		c.ReportCheckHealthState = ok
	}

	if limit, err := strconv.Atoi(os.Getenv("STS_PROCESS_AGENT_HEALTH_STATE_MESSAGE_LIMIT")); err == nil && limit != 0 {
		c.CheckHealthStateMessageLimit = limit
	}

	if ok, err := isAffirmative(os.Getenv("STS_PROTOCOL_INSPECTION_ENABLED")); err == nil {
		c.NetworkTracer.EnableProtocolInspection = ok
	}

	if ok, err := isAffirmative(os.Getenv("STS_HTTPS_INSPECTION_ENABLED")); err == nil {
		c.NetworkTracer.EnableHTTPSInspection = ok
	}

	if ok, err := isAffirmative(os.Getenv("STS_HTTP_TRACING_ENABLED")); err == nil {
		c.NetworkTracer.EnableHTTPTracing = ok
	}

	if ok, err := isAffirmative(os.Getenv("STS_PROBE_DEBUG_LOG_ENABLED")); err == nil {
		c.NetworkTracer.ProbeDebugLog = ok
	}

	if maxStats, err := strconv.Atoi(os.Getenv("STS_HTTP_STATS_BUFFER_SIZE")); err == nil && maxStats != 0 {
		c.NetworkTracer.MaxHTTPStatsBuffered = maxStats
	}

	if maxObs, err := strconv.Atoi(os.Getenv("STS_HTTP_OBSERVATIONS_BUFFER_SIZE")); err == nil && maxObs != 0 {
		c.NetworkTracer.MaxHTTPObservationsBuffered = maxObs
	}

	if v := os.Getenv("STS_DISABLED_PROTOCOLS"); v != "" {
		protocols := strings.Split(v, ",")
		for i, proto := range protocols {
			protocols[i] = strings.ToLower(proto)
		}
		c.NetworkTracer.DisabledProtocols = protocols
	}

	var patterns []string
	amountTopCPUPercentageUsage, amountTopIOReadUsage, amountTopIOWriteUsage, amountTopMemoryUsage := -1, -1, -1, -1
	CPUPercentageUsageThreshold, memoryUsageThreshold := 0, 0
	if v := os.Getenv("STS_PROCESS_BLACKLIST_PATTERNS"); v != "" {
		patterns = strings.Split(v, ",")
	}
	if v, err := strconv.Atoi(os.Getenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_CPU")); err == nil {
		amountTopCPUPercentageUsage = v
	}
	if v, err := strconv.Atoi(os.Getenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_IO_READ")); err == nil {
		amountTopIOReadUsage = v
	}
	if v, err := strconv.Atoi(os.Getenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_IO_WRITE")); err == nil {
		amountTopIOWriteUsage = v
	}
	if v, err := strconv.Atoi(os.Getenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_MEM")); err == nil {
		amountTopMemoryUsage = v
	}
	if v, err := strconv.Atoi(os.Getenv("STS_PROCESS_BLACKLIST_INCLUSIONS_CPU_THRESHOLD")); err == nil {
		CPUPercentageUsageThreshold = v
	}
	if v, err := strconv.Atoi(os.Getenv("STS_PROCESS_BLACKLIST_INCLUSIONS_MEM_THRESHOLD")); err == nil {
		memoryUsageThreshold = v
	}
	setProcessBlacklist(c,
		patterns,
		amountTopCPUPercentageUsage, amountTopIOReadUsage, amountTopIOWriteUsage, amountTopMemoryUsage,
		CPUPercentageUsageThreshold, memoryUsageThreshold)

	if v := os.Getenv("STS_CLUSTER_NAME"); v != "" {
		c.ClusterName = v
	}

	if v := os.Getenv("STS_PROCESS_CACHE_DURATION_MIN"); v != "" {
		durationS, _ := strconv.Atoi(v)
		c.ProcessCacheDurationMin = time.Duration(durationS) * time.Minute
	}

	if v := os.Getenv("STS_NETWORK_RELATION_CACHE_DURATION_MIN"); v != "" {
		durationS, _ := strconv.Atoi(v)
		c.NetworkRelationCacheDurationMin = time.Duration(durationS) * time.Minute
	}

	if v := os.Getenv("STS_NETWORK_TRACER_INIT_RETRY_DURATION_SEC"); v != "" {
		durationS, _ := strconv.Atoi(v)
		c.NetworkTracerInitRetryDuration = time.Duration(durationS) * time.Second
	}

	if v := os.Getenv("STS_NETWORK_TRACER_MAX_CONNECTIONS"); v != "" {
		maxConnections, _ := strconv.Atoi(v)
		c.NetworkTracerMaxConnections = maxConnections
	}

	if v := os.Getenv("STS_MAX_PROCESSES_PER_MESSAGE"); v != "" {
		maxConnections, _ := strconv.Atoi(v)
		c.MaxPerMessage = maxConnections
	}

	if v := os.Getenv("STS_MAX_CONNECTIONS_PER_MESSAGE"); v != "" {
		maxConnections, _ := strconv.Atoi(v)
		c.MaxConnectionsPerMessage = maxConnections
	}

	if v, err := strconv.Atoi(os.Getenv("STS_NETWORK_TRACER_INIT_RETRY_AMOUNT")); err == nil {
		c.NetworkTracerInitRetryAmount = v
	}

	if v, err := strconv.Atoi(os.Getenv("STS_PROCESS_FILTER_SHORT_LIVED_QUALIFIER_SECS")); err == nil {
		setProcessFilters(c, true, v)
	}

	if v, err := strconv.Atoi(os.Getenv("STS_NETWORK_RELATION_FILTER_SHORT_LIVED_QUALIFIER_SECS")); err == nil {
		setNetworkRelationFilters(c, true, v)
	}

	// STS
	if v, err := strconv.Atoi(os.Getenv("STS_PROCESS_CHECK_INTERVAL")); err == nil {
		c.CheckIntervals["process"] = time.Duration(v) * time.Second
	}

	if v, err := strconv.Atoi(os.Getenv("STS_CONNECTION_CHECK_INTERVAL")); err == nil {
		c.CheckIntervals["connections"] = time.Duration(v) * time.Second
	}

	if v, err := strconv.Atoi(os.Getenv("STS_TX_MANAGER_CHANNEL_BUFFER_SIZE")); err == nil {
		c.TxManagerChannelBufferSize = v
	}

	if v, err := strconv.Atoi(os.Getenv("STS_TX_MANAGER_TIMEOUT_DURATION_SECONDS")); err == nil {
		c.TxManagerTimeoutDurationSeconds = time.Duration(v) * time.Second
	}

	if v, err := strconv.Atoi(os.Getenv("STS_TX_MANAGER_EVICTION_DURATION_SECONDS")); err == nil {
		c.TxManagerEvictionDurationSeconds = time.Duration(v) * time.Second
	}

	if v, err := strconv.Atoi(os.Getenv("STS_TX_MANAGER_TICKER_INTERVAL_SECONDS")); err == nil {
		c.TxManagerTickerIntervalSeconds = time.Duration(v) * time.Second
	}

	if v, err := strconv.Atoi(os.Getenv("STS_BATCHER_MAX_BUFFER_SIZE")); err == nil {
		c.BatcherMaxBufferSize = v
	}

	if enabled, _ := isAffirmative(os.Getenv("STS_BATCHER_LOG_PAYLOADS")); enabled {
		c.BatcherLogPayloads = enabled
	}

	if v := os.Getenv("STS_SKIP_SSL_VALIDATION"); v != "" {
		c.SkipSSLValidation = true
	}

	if tlsValue := os.Getenv("STS_SKIP_KUBELET_TLS_VERIFY"); tlsValue != "" {
		c.SkipKubeletTLSVerify, _ = isAffirmative(tlsValue)
	}

	if v := os.Getenv("STS_KUBERNETES_KUBELET_HOST"); v != "" {
		c.KubernetesKubeletHost = v
	}

	if v := os.Getenv("STS_CRI_SOCKET_PATH"); v != "" {
		c.CriSocketPath = v
	}

	if enabled, _ := isAffirmative(os.Getenv("STS_HTTP_STATS_PER_PATH")); enabled {
		c.HTTPStatsPerPath = enabled
	}

	return c
}

func setProcessBlacklist(agentConf *AgentConfig,
	patterns []string,
	amountTopCPUPercentageUsage int, amountTopIOReadUsage int, amountTopIOWriteUsage int, amountTopMemoryUsage int,
	CPUPercentageUsageThreshold int, MemoryUsageThreshold int,
) {
	if len(patterns) > 0 {
		log.Infof("Overriding processes blacklist to %v", patterns)
		agentConf.Blacklist = deriveFmapConstructRegex(constructRegex, patterns)
	} else {
		log.Infof("Using default processes blacklist.", agentConf.Blacklist)
	}
	if amountTopCPUPercentageUsage >= 0 {
		log.Infof("Overriding top CPU percentage using processes inclusions to %d", amountTopCPUPercentageUsage)
		agentConf.AmountTopCPUPercentageUsage = amountTopCPUPercentageUsage
	}
	if amountTopIOReadUsage >= 0 {
		log.Infof("Overriding top IO read using processes inclusions to %d", amountTopIOReadUsage)
		agentConf.AmountTopIOReadUsage = amountTopIOReadUsage
	}
	if amountTopIOWriteUsage >= 0 {
		log.Infof("Overriding top IO write using processes inclusions to %d", amountTopIOWriteUsage)
		agentConf.AmountTopIOWriteUsage = amountTopIOWriteUsage
	}
	if amountTopMemoryUsage >= 0 {
		log.Infof("Overriding top memory using processes inclusions to %d", amountTopMemoryUsage)
		agentConf.AmountTopMemoryUsage = amountTopMemoryUsage
	}

	// Threshold for retrieving top CPU percentage using processes
	if CPUPercentageUsageThreshold != 0 {
		log.Infof("Overriding CPU percentage threshold for collecting top CPU using processes inclusions to %d", CPUPercentageUsageThreshold)
		agentConf.CPUPercentageUsageThreshold = CPUPercentageUsageThreshold
		if amountTopCPUPercentageUsage <= 0 {
			log.Warn("CPUPercentageUsageThreshold specified without AmountTopCPUPercentageUsage. Please add AmountTopCPUPercentageUsage to benefit from the top process inclusions")
		}
	}

	// Threshold for retrieving top Memory percentage using processes
	if MemoryUsageThreshold != 0 {
		log.Infof("Overriding Memory threshold for collecting top memory using processes inclusions to %d", MemoryUsageThreshold)
		agentConf.MemoryUsageThreshold = MemoryUsageThreshold
		if amountTopMemoryUsage <= 0 {
			log.Warn("MemoryUsageThreshold specified without AmountTopMemoryUsage. Please add AmountTopMemoryUsage to benefit from the top process inclusions")
		}
	}

	// log warning if blacklist inclusions is specified without patterns
	if (agentConf.AmountTopCPUPercentageUsage > 0 ||
		agentConf.AmountTopIOReadUsage > 0 ||
		agentConf.AmountTopIOWriteUsage > 0 ||
		agentConf.AmountTopMemoryUsage > 0) && len(agentConf.Blacklist) == 0 {
		log.Warn("Process blacklist inclusions specified without a blacklist pattern. Please add process blacklist patterns to benefit from the top process inclusions")
	}

}

// setProcessFilters sets the short-lived process filters
func setProcessFilters(agentConf *AgentConfig, enableShortLivedProcessFilter bool, shortLivedProcessQualifierSecs int) {
	if enableShortLivedProcessFilter && shortLivedProcessQualifierSecs > 0 {
		agentConf.EnableShortLivedProcessFilter = enableShortLivedProcessFilter
	} else {
		agentConf.EnableShortLivedProcessFilter = false
	}
	agentConf.ShortLivedProcessQualifierSecs = time.Duration(shortLivedProcessQualifierSecs) * time.Second
}

// setNetworkRelationFilters sets the short-lived relation filters
func setNetworkRelationFilters(agentConf *AgentConfig, enableShortLivedNetworkRelationFilter bool, shortLivedNetworkRelationQualifierSecs int) {
	if enableShortLivedNetworkRelationFilter && shortLivedNetworkRelationQualifierSecs > 0 {
		agentConf.EnableShortLivedNetworkRelationFilter = enableShortLivedNetworkRelationFilter
	} else {
		agentConf.EnableShortLivedNetworkRelationFilter = false
	}
	agentConf.ShortLivedNetworkRelationQualifierSecs = time.Duration(shortLivedNetworkRelationQualifierSecs) * time.Second
}

func constructRegex(pattern string) *regexp.Regexp {
	r, err := regexp.Compile(pattern)
	if err != nil {
		log.Warnf("Invalid blacklist pattern: %s", pattern)
	}
	return r
}

// IsBlacklisted returns a boolean indicating if the given command is blacklisted by our config.
func IsBlacklisted(cmdline []string, blacklist []*regexp.Regexp) bool {
	cmd := strings.Join(cmdline, " ")
	for _, b := range blacklist {
		if b.MatchString(cmd) {
			log.Debugf("Filter process: %s based on blacklist: %s", cmd, b.String())
			return true
		}
	}

	log.Debugf("Not filtering process: %s", cmd)
	return false
}

func isAffirmative(value string) (bool, error) {
	if value == "" {
		return false, fmt.Errorf("value is empty")
	}
	v := strings.ToLower(value)
	return v == "true" || v == "yes" || v == "1", nil
}

// ConfigureHostname puts the hostname into the config. This has been separateded to allow the rest of the config to be processed before finding the hostname
func ConfigureHostname(cfg *AgentConfig) {
	// Get hostname from agent util since the process-agent image doesn't include the main agent
	if cfg.HostName == "" {
		if hostname, err := hostname.Get(context.TODO()); err == nil {
			cfg.HostName = hostname
			log.Debugf("Got hostname from agent util")
		}
	}
	log.Infof("Hostname is: %s", cfg.HostName)
}

// IsContainerized returns whether the Agent is running on a Docker container
func IsContainerized() bool {
	return os.Getenv("DOCKER_STS_AGENT") != ""
}
