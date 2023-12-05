package config

import (
	"github.com/DataDog/datadog-agent/pkg/ebpf"
	tracerConfig "github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	log "github.com/cihub/seelog"
	"time"
)

// TracerConfig creates a config for the network tracer
func TracerConfig(cfg *AgentConfig) *tracerConfig.Config {
	// Defaults taken from datadog
	const defaultUDPTimeoutSeconds = 30
	const defaultUDPStreamTimeoutSeconds = 120
	const defaultOffsetThreshold = 400

	c := &tracerConfig.Config{
		Config: EBPFConfig(cfg),

		NPMEnabled:               true,
		ServiceMonitoringEnabled: true,

		CollectTCPConns:  true,
		TCPConnTimeout:   2 * time.Minute,
		TCPClosedTimeout: 1 * time.Second,

		CollectUDPConns:  false,
		UDPConnTimeout:   defaultUDPTimeoutSeconds * time.Second,
		UDPStreamTimeout: defaultUDPStreamTimeoutSeconds * time.Second,

		CollectIPv6Conns:               true,
		OffsetGuessThreshold:           defaultOffsetThreshold,
		ExcludedSourceConnections:      map[string][]string{},
		ExcludedDestinationConnections: map[string][]string{},

		MaxTrackedConnections:          uint(cfg.NetworkTracerMaxConnections),
		MaxClosedConnectionsBuffered:   cfg.NetworkTracerMaxConnections,
		ClosedConnectionFlushThreshold: 0,
		ClosedChannelSize:              500,
		MaxConnectionsStateBuffered:    75000,
		ClientStateExpiry:              2 * time.Minute,

		DNSInspection:       false,
		CollectDNSStats:     false,
		CollectLocalDNS:     false,
		CollectDNSDomains:   false,
		MaxDNSStats:         20000,
		MaxDNSStatsBuffered: 75000,
		DNSTimeout:          15 * time.Second,

		ProtocolClassificationEnabled: cfg.NetworkTracer.EnableProtocolInspection,

		EnableHTTPMonitoring:        cfg.NetworkTracer.EnableProtocolInspection,
		EnableHTTPSMonitoring:       cfg.NetworkTracer.EnableProtocolInspection && cfg.NetworkTracer.EnableHTTPSInspection,
		EnableHTTPTracing:           cfg.NetworkTracer.EnableHTTPTracing,
		ProbeDebugLog:               cfg.NetworkTracer.ProbeDebugLog,
		ProbeLogBufferSizeBytes:     cfg.NetworkTracer.ProbeLogBufferSizeBytes,
		MaxHTTPStatsBuffered:        cfg.NetworkTracer.MaxHTTPStatsBuffered,        // 100000,
		MaxHTTPObservationsBuffered: cfg.NetworkTracer.MaxHTTPObservationsBuffered, // 100000 is the default from datadog

		MaxTrackedHTTPConnections: 1024,
		HTTPNotificationThreshold: 512,
		HTTPMaxRequestFragment:    160,

		EnableConntrack:              true,
		ConntrackMaxStateSize:        131072,
		ConntrackRateLimit:           500,
		ConntrackRateLimitInterval:   3 * time.Second,
		EnableConntrackAllNamespaces: true,
		IgnoreConntrackInitFailure:   false,
		ConntrackInitTimeout:         10 * time.Second,

		EnableGatewayLookup: true,

		EnableMonotonicCount: true,

		RecordedQueryTypes: []string{},

		EnableRootNetNs: true,

		HTTPMapCleanerInterval: 300 * time.Second,
		HTTPIdleConnectionTTL:  30 * time.Second,

		// Service Monitoring
		EnableJavaTLSSupport: false,
		EnableGoTLSSupport:   false,
	}

	if c.HTTPNotificationThreshold >= c.MaxTrackedHTTPConnections {
		log.Warnf("Notification threshold set higher than tracked connections.  %d > %d ; resetting to %d",
			c.HTTPNotificationThreshold, c.MaxTrackedHTTPConnections, c.MaxTrackedHTTPConnections/2)
		c.HTTPNotificationThreshold = c.MaxTrackedHTTPConnections / 2
	}

	maxHTTPFrag := uint64(160)
	if c.HTTPMaxRequestFragment > int64(maxHTTPFrag) { // dbtodo where is the actual max defined?
		log.Warnf("Max HTTP fragment too large (%d) resetting to (%d) ", c.HTTPMaxRequestFragment, maxHTTPFrag)
		c.HTTPMaxRequestFragment = int64(maxHTTPFrag)
	}

	if !kernel.IsIPv6Enabled() {
		c.CollectIPv6Conns = false
		log.Info("network tracer IPv6 tracing disabled by system")
	} else if !c.CollectIPv6Conns {
		log.Info("network tracer IPv6 tracing disabled by configuration")
	}

	if !c.CollectUDPConns {
		log.Info("network tracer UDP tracing disabled by configuration")
	}
	if !c.CollectTCPConns {
		log.Info("network tracer TCP tracing disabled by configuration")
	}
	if !c.DNSInspection {
		log.Info("network tracer DNS inspection disabled by configuration")
	}

	if !c.EnableRootNetNs {
		c.EnableConntrackAllNamespaces = false
	}

	return c
}

// EBPFConfig creates a config with ebpf-related settings
func EBPFConfig(cfg *AgentConfig) ebpf.Config {
	return ebpf.Config{
		BPFDebug:                 false,
		BPFDir:                   cfg.NetworkTracer.EbpfArtifactDir,
		JavaDir:                  "", // Dummy value, we do not support java TLS right now (does it work on k8s?)
		ExcludedBPFLinuxVersions: []string{},
		EnableTracepoints:        false,
		ProcRoot:                 util.GetProcRoot(),

		EnableCORE: true,
		BTFPath:    "", // No btf support for now

		// Runtime compilation is disabled for now
		EnableRuntimeCompiler:        false,
		RuntimeCompilerOutputDir:     "",
		EnableKernelHeaderDownload:   false,
		KernelHeadersDirs:            []string{},
		KernelHeadersDownloadDir:     "",
		AptConfigDir:                 "",
		YumReposDir:                  "",
		ZypperReposDir:               "",
		AllowPrecompiledFallback:     false,
		AllowRuntimeCompiledFallback: false,

		AttachKprobesWithKprobeEventsABI: false,
	}
}
