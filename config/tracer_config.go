package config

import (
	"time"

	"github.com/DataDog/datadog-agent/pkg/ebpf"
	tracerConfig "github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	log "github.com/cihub/seelog"
	"k8s.io/utils/strings/slices"
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

		CollectTCPv4Conns: true,
		TCPConnTimeout:    2 * time.Minute,

		CollectUDPv4Conns: false,
		UDPConnTimeout:    defaultUDPTimeoutSeconds * time.Second,
		UDPStreamTimeout:  defaultUDPStreamTimeoutSeconds * time.Second,

		CollectTCPv6Conns:              true,
		OffsetGuessThreshold:           defaultOffsetThreshold,
		ExcludedSourceConnections:      map[string][]string{},
		ExcludedDestinationConnections: map[string][]string{},

		MaxTrackedConnections:          uint32(cfg.NetworkTracerMaxConnections),
		MaxClosedConnectionsBuffered:   uint32(cfg.NetworkTracerMaxConnections),
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

		EnableHTTPMonitoring:  cfg.NetworkTracer.EnableProtocolInspection && !slices.Contains(cfg.NetworkTracer.DisabledProtocols, HTTPProtocolName),
		EnableHTTP2Monitoring: cfg.NetworkTracer.EnableProtocolInspection && !slices.Contains(cfg.NetworkTracer.DisabledProtocols, HTTP2ProtocolName),

		EnableKafkaMonitoring: false,

		EnableMongoMonitoring: cfg.NetworkTracer.EnableProtocolInspection && !slices.Contains(cfg.NetworkTracer.DisabledProtocols, MongoProtocolName),
		MaxMongoStatsBuffered: 100000,

		EnableAMQPMonitoring: cfg.NetworkTracer.EnableProtocolInspection && !slices.Contains(cfg.NetworkTracer.DisabledProtocols, AMQPProtocolName),
		MaxAMQPStatsBuffered: 100000,

		EnablePostgresMonitoring:   cfg.NetworkTracer.EnableProtocolInspection && !slices.Contains(cfg.NetworkTracer.DisabledProtocols, PostgresProtocolName),
		MaxPostgresStatsBuffered:   100000,
		MaxPostgresTelemetryBuffer: 160, // Default value from DataDog

		EnableNativeTLSMonitoring: cfg.NetworkTracer.EnableProtocolInspection && !slices.Contains(cfg.NetworkTracer.DisabledProtocols, TLSProtocolName),
		EnableIstioMonitoring:     false,
		EnableGoTLSSupport:        false,

		EnableHTTPTracing:           cfg.NetworkTracer.EnableHTTPTracing,
		ProbeDebugLog:               cfg.NetworkTracer.ProbeDebugLog,
		MaxHTTPStatsBuffered:        cfg.NetworkTracer.MaxHTTPStatsBuffered,        // 100000,
		MaxHTTPObservationsBuffered: cfg.NetworkTracer.MaxHTTPObservationsBuffered, // 100000 is the default from datadog

		MaxTrackedHTTPConnections: 1024,
		MaxUSMConcurrentRequests:  1024,
		HTTPNotificationThreshold: 512,
		HTTPMaxRequestFragment:    160,

		EnableConntrack:       true,
		EnableEbpfConntracker: true,

		// At the moment we disable it by default, this is a new feature from the 7.62.2 sync.
		// Let's see if we need it in the future.
		EnableCiliumLBConntracker:    false,
		ConntrackMaxStateSize:        131072,
		ConntrackRateLimit:           500,
		ConntrackRateLimitInterval:   3 * time.Second,
		EnableConntrackAllNamespaces: true,
		IgnoreConntrackInitFailure:   false,
		ConntrackInitTimeout:         120 * time.Second,

		EnableGatewayLookup: true,

		EnableMonotonicCount: true,

		RecordedQueryTypes: []string{},

		EnableRootNetNs: true,

		HTTP2DynamicTableMapCleanerInterval: 300 * time.Second,

		HTTPMapCleanerInterval: 300 * time.Second,
		HTTPIdleConnectionTTL:  30 * time.Second,
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
		c.CollectTCPv6Conns = false
		log.Info("network tracer IPv6 tracing disabled by system")
	} else if !c.CollectTCPv6Conns {
		log.Info("network tracer IPv6 tracing disabled by configuration")
	}

	if !c.CollectUDPv4Conns {
		log.Info("network tracer UDP tracing disabled by configuration")
	}
	if !c.CollectTCPv4Conns {
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
		ExcludedBPFLinuxVersions: []string{},
		EnableTracepoints:        false,
		ProcRoot:                 kernel.ProcFSRoot(),

		EnableCORE:                   false,
		EnableRuntimeCompiler:        false,
		AllowRuntimeCompiledFallback: false,

		// Should be irrilevant for us since we disable CORE and runtime compiler.
		// Put it to `true` just to highlight that we want to fallback to the prebuilt mode.
		AllowPrebuiltFallback: true,

		BTFPath: "", // No btf support for now

		RuntimeCompilerOutputDir:   "/opt/stackstate-agent/runtime-compiler-output",
		EnableKernelHeaderDownload: false,
		KernelHeadersDirs:          []string{"/opt/stackstate-agent/kernel-headers"},
		KernelHeadersDownloadDir:   "/tmp",
		AptConfigDir:               "/etc/apt",
		YumReposDir:                "/etc/yum.repos.d",
		ZypperReposDir:             "/etc/zypp/repos.d",

		AttachKprobesWithKprobeEventsABI: false,
	}
}
