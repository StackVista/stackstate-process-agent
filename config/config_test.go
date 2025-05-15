package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/gopsutil/process"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
	"k8s.io/utils/strings/slices"
)

func TestBlacklist(t *testing.T) {
	testBlacklist := defaultBlacklistPatterns
	blacklist := make([]*regexp.Regexp, 0, len(testBlacklist))
	for _, b := range testBlacklist {
		r, err := regexp.Compile(b)
		if err == nil {
			blacklist = append(blacklist, r)
		}
	}
	cases := []struct {
		cmdline     []string
		blacklisted bool
	}{
		{[]string{"/pause"}, true},
		{[]string{"/usr/local/bin/k3s server"}, true},
	}

	for _, c := range cases {
		assert.Equal(t, c.blacklisted, IsBlacklisted(c.cmdline, blacklist),
			fmt.Sprintf("Case %v failed", c))
	}
}

func TestBlacklistIncludeOnly(t *testing.T) {
	testBlacklist := []string{
		"^[^bla].*",
	}
	blacklist := make([]*regexp.Regexp, 0, len(testBlacklist))
	for _, b := range testBlacklist {
		r, err := regexp.Compile(b)
		if err == nil {
			blacklist = append(blacklist, r)
		}
	}
	cases := []struct {
		cmdline     []string
		blacklisted bool
	}{
		{[]string{"getty", "-foo", "-bar"}, true},
		{[]string{"rpcbind", "-x"}, true},
		{[]string{"my-rpc-app", "-config foo.ini"}, true},
		{[]string{"rpc.statd", "-L"}, true},
		{[]string{"bla"}, false},
		{[]string{"bla -w arguments"}, false},
	}

	for _, c := range cases {
		assert.Equal(t, c.blacklisted, IsBlacklisted(c.cmdline, blacklist),
			fmt.Sprintf("Case %v failed", c))
	}
}

func TestDefaultBlacklist(t *testing.T) {
	var cf *YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"anything: goes",
	}, "\n")), &cf)
	assert.NoError(t, err)

	agentConfig, _ := NewAgentConfig(cf)
	assert.True(t, IsBlacklisted([]string{"/usr/sbin/acpid"}, agentConfig.Blacklist))
}

func TestDefaultBlacklistNix(t *testing.T) {
	var cf *YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"anything: goes",
	}, "\n")), &cf)
	assert.NoError(t, err)
	agentConfig, _ := NewAgentConfig(cf)

	for _, tc := range []struct {
		name        string
		processArgs []string
		expected    bool
	}{
		{
			name:        "Should not filter /opt/some-application/bin/app process based on Blacklist",
			processArgs: []string{"/opt/some-application/bin/app", "start", "-h"},
			expected:    false,
		},
		{
			name:        "Should not filter /usr/bin/python2.7 process based on Blacklist",
			processArgs: []string{"/usr/bin/python2.7", "my-py-application"},
			expected:    false,
		},
		{
			name:        "Should not filter /usr/local/openjdk-8/bin/java process based on Blacklist",
			processArgs: []string{"/usr/local/openjdk-8/bin/java", "my-java-application"},
			expected:    false,
		},
		{
			name:        "Should filter sleep process based on Blacklist",
			processArgs: []string{"sleep", "15"},
			expected:    true,
		},
		{
			name:        "Should filter -sh process based on Blacklist",
			processArgs: []string{"-sh", "something"},
			expected:    true,
		},
		{
			name:        "Should filter msdtc.exe process based on Blacklist",
			processArgs: []string{"sshd:", ""},
			expected:    true,
		},
		{
			name:        "Should filter pause process based on Blacklist",
			processArgs: []string{"pause"},
			expected:    true,
		},
		{
			name:        "Should filter /usr/bin/vim process based on Blacklist",
			processArgs: []string{"/usr/bin/vim", "some-text-file"},
			expected:    true,
		},
		{
			name:        "Should filter everything in /usr/sbin based on Blacklist",
			processArgs: []string{"/usr/sbin/everything"},
			expected:    true,
		},
		{
			name:        "Should filter s6-format-filter process based on Blacklist",
			processArgs: []string{"s6-format-filter"},
			expected:    true,
		},
		{
			name:        "Should filter dotnet process based on Blacklist",
			processArgs: []string{"dotnet", "my-dotnet-application"},
			expected:    true,
		},
		{
			name:        "Should filter /usr/bin/containerd process based on Blacklist",
			processArgs: []string{"/usr/bin/containerd"},
			expected:    true,
		},
		{
			name:        "Should filter bash process based on Blacklist",
			processArgs: []string{"bash", "some-bash-process"},
			expected:    true,
		},
		{
			name:        "Should filter docker-container-shim process based on Blacklist",
			processArgs: []string{"docker-container-shim"},
			expected:    true,
		},
		{
			name:        "Should filter kubelet process in Kubernetes based on Blacklist",
			processArgs: []string{"/usr/local/bin/kubelet", "--some", "--extra=path", "arguments", "--config=/var/lib/kubelet/kubelet.conf"},
			expected:    true,
		},
		{
			name:        "Should filter kubelet process in Kubernetes based on Blacklist",
			processArgs: []string{"/usr/bin/kubelet", "--some", "--extra=path", "arguments", "--config=/var/lib/kubelet/kubelet.conf"},
			expected:    true,
		},
		{
			name:        "Should filter kubelet process in OpenShift based on Blacklist",
			processArgs: []string{"kubelet", "--config=/etc/kubernetes/kubelet.conf"},
			expected:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filter := IsBlacklisted(tc.processArgs, agentConfig.Blacklist)
			assert.Equal(t, tc.expected, filter, "Test: [%s], expected filter: %t, found filter: %t", tc.name, tc.expected, filter)
		})
	}
}

func TestSetFiltersFromEnv(t *testing.T) {
	os.Setenv("STS_PROCESS_CACHE_DURATION_MIN", "2")
	os.Setenv("STS_NETWORK_RELATION_CACHE_DURATION_MIN", "4")
	os.Setenv("STS_PROCESS_FILTER_SHORT_LIVED_QUALIFIER_SECS", "0")
	os.Setenv("STS_NETWORK_RELATION_FILTER_SHORT_LIVED_QUALIFIER_SECS", "45")

	agentConfig, _ := NewAgentConfig(nil)

	assert.Equal(t, 2*time.Minute, agentConfig.ProcessCacheDurationMin)
	assert.Equal(t, 4*time.Minute, agentConfig.NetworkRelationCacheDurationMin)
	assert.Equal(t, false, agentConfig.EnableShortLivedProcessFilter)
	assert.Equal(t, 0*time.Second, agentConfig.ShortLivedProcessQualifierSecs)
	assert.Equal(t, true, agentConfig.EnableShortLivedNetworkRelationFilter)
	assert.Equal(t, 45*time.Second, agentConfig.ShortLivedNetworkRelationQualifierSecs)

	os.Unsetenv("STS_PROCESS_CACHE_DURATION_MIN")
	os.Unsetenv("STS_NETWORK_RELATION_CACHE_DURATION_MIN")
	os.Unsetenv("STS_PROCESS_FILTER_SHORT_LIVED_QUALIFIER_SECS")
	os.Unsetenv("STS_NETWORK_RELATION_FILTER_SHORT_LIVED_QUALIFIER_SECS")
}

func TestSetBlacklistFromEnv(t *testing.T) {
	os.Setenv("STS_PROCESS_BLACKLIST_PATTERNS", "^/usr/bin/bashbash,^sshd:")

	os.Setenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_CPU", "2")
	os.Setenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_IO_READ", "4")
	os.Setenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_IO_WRITE", "5")
	os.Setenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_MEM", "6")
	os.Setenv("STS_PROCESS_BLACKLIST_INCLUSIONS_CPU_THRESHOLD", "30")
	os.Setenv("STS_PROCESS_BLACKLIST_INCLUSIONS_MEM_THRESHOLD", "25")

	agentConfig, _ := NewAgentConfig(nil)
	assert.Equal(t, len(agentConfig.Blacklist), 2)

	assert.Equal(t, agentConfig.AmountTopCPUPercentageUsage, 2)
	assert.Equal(t, agentConfig.AmountTopIOReadUsage, 4)
	assert.Equal(t, agentConfig.AmountTopIOWriteUsage, 5)
	assert.Equal(t, agentConfig.AmountTopMemoryUsage, 6)
	assert.Equal(t, agentConfig.CPUPercentageUsageThreshold, 30)
	assert.Equal(t, agentConfig.MemoryUsageThreshold, 25)

	os.Unsetenv("STS_PROCESS_BLACKLIST_PATTERNS")
	os.Unsetenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_CPU")
	os.Unsetenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_IO_READ")
	os.Unsetenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_IO_WRITE")
	os.Unsetenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_MEM")
	os.Unsetenv("STS_PROCESS_BLACKLIST_INCLUSIONS_CPU_THRESHOLD")
	os.Unsetenv("STS_PROCESS_BLACKLIST_INCLUSIONS_MEM_THRESHOLD")
}

func TestSetNetworkTracerInitRetryFromEnv(t *testing.T) {
	os.Setenv("STS_NETWORK_TRACER_INIT_RETRY_DURATION_SEC", "30")
	os.Setenv("STS_NETWORK_TRACER_INIT_RETRY_AMOUNT", "4")

	agentConfig, _ := NewAgentConfig(nil)

	assert.Equal(t, 30*time.Second, agentConfig.NetworkTracerInitRetryDuration)
	assert.Equal(t, 4, agentConfig.NetworkTracerInitRetryAmount)

	os.Unsetenv("STS_NETWORK_TRACER_INIT_RETRY_DURATION_SEC")
	os.Unsetenv("STS_NETWORK_TRACER_INIT_RETRY_AMOUNT")
}

func TestOnlyEnvConfig(t *testing.T) {
	// setting an API Key should be enough to generate valid config
	os.Setenv("STS_API_KEY", "apikey_from_env")

	agentConfig, _ := NewAgentConfig(nil)
	assert.Equal(t, "apikey_from_env", agentConfig.APIEndpoints[0].APIKey)

	os.Setenv("STS_API_KEY", "")
}

func TestOnlyEnvConfigArgsScrubbingEnabled(t *testing.T) {
	os.Setenv("STS_CUSTOM_SENSITIVE_WORDS", "*password*,consul_token,*api_key")

	agentConfig, _ := NewAgentConfig(nil)
	assert.Equal(t, true, agentConfig.Scrubber.Enabled)

	cases := []struct {
		cmdline       []string
		parsedCmdline []string
	}{
		{
			[]string{"spidly", "--mypasswords=123,456", "consul_token", "1234", "--dd_api_key=1234"},
			[]string{"spidly", "--mypasswords=********", "consul_token", "********", "--dd_api_key=********"},
		},
	}

	for i := range cases {
		cases[i].cmdline, _ = agentConfig.Scrubber.scrubCommand(cases[i].cmdline)
		assert.Equal(t, cases[i].parsedCmdline, cases[i].cmdline)
	}

	os.Setenv("STS_CUSTOM_SENSITIVE_WORDS", "")
}

func TestOnlyEnvConfigArgsScrubbingDisabled(t *testing.T) {
	os.Setenv("STS_SCRUB_ARGS", "false")
	os.Setenv("STS_CUSTOM_SENSITIVE_WORDS", "*password*,consul_token,*api_key")

	agentConfig, _ := NewAgentConfig(nil)
	assert.Equal(t, false, agentConfig.Scrubber.Enabled)

	cases := []struct {
		cmdline       []string
		parsedCmdline []string
	}{
		{
			[]string{"spidly", "--mypasswords=123,456", "consul_token", "1234", "--dd_api_key=1234"},
			[]string{"spidly", "--mypasswords=123,456", "consul_token", "1234", "--dd_api_key=1234"},
		},
	}

	for i := range cases {
		fp := &process.FilledProcess{Cmdline: cases[i].cmdline}
		cases[i].cmdline = agentConfig.Scrubber.ScrubProcessCommand(fp)
		assert.Equal(t, cases[i].parsedCmdline, cases[i].cmdline)
	}

	os.Setenv("STS_SCRUB_ARGS", "")
	os.Setenv("STS_CUSTOM_SENSITIVE_WORDS", "")
}

func TestDefaultConfig(t *testing.T) {
	assert := assert.New(t)
	agentConfig := NewDefaultAgentConfig()

	// assert that some sane defaults are set
	assert.Equal("info", agentConfig.LogLevel)
	assert.Equal(processChecks, agentConfig.EnabledChecks) // sts
	assert.Equal(true, agentConfig.Scrubber.Enabled)

	os.Setenv("DOCKER_STS_AGENT", "yes")
	agentConfig = NewDefaultAgentConfig()
	if pathExists("/host") {
		assert.Equal(os.Getenv("HOST_PROC"), "/host/proc")
		assert.Equal(os.Getenv("HOST_SYS"), "/host/sys")
	} else {
		assert.Equal(os.Getenv("HOST_PROC"), "")
		assert.Equal(os.Getenv("HOST_SYS"), "")
	}
	os.Setenv("DOCKER_STS_AGENT", "no")
	assert.Equal(processChecks, agentConfig.EnabledChecks) // sts
}

func TestAgentConfigYamlOnly(t *testing.T) {
	assert := assert.New(t)
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"sts_url: 'https://stackstate.com'",
		"api_key: apikey_20",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'true'",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
		"  windows:",
		"    args_refresh_interval: 100",
		"    add_new_args: false",
		"  scrub_args: false",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(&ddy)
	assert.NoError(err)

	ep := agentConfig.APIEndpoints[0]
	assert.Equal("apikey_20", ep.APIKey)
	assert.Equal("stackstate.com", ep.Endpoint.Hostname())
	assert.Equal(10, agentConfig.QueueSize)
	assert.Equal(true, agentConfig.Enabled)
	assert.Equal(true, agentConfig.EnableIncrementalPublishing)
	assert.Equal(1*time.Minute, agentConfig.IncrementalPublishingRefreshInterval)
	assert.Equal(processChecks, agentConfig.EnabledChecks)
	assert.Equal(8*time.Second, agentConfig.CheckIntervals["container"])
	assert.Equal(30*time.Second, agentConfig.CheckIntervals["process"])
	assert.Equal(false, agentConfig.Scrubber.Enabled)

	ddy = YamlAgentConfig{}
	err = yaml.Unmarshal([]byte(strings.Join([]string{
		"sts_url: 'https://stackstate.com'",
		"api_key: apikey_20",
		"process_agent_enabled: true",
		"incremental_publishing_enabled: false",
		"incremental_publishing_refresh_interval: 120",
		"process_config:",
		"  enabled: 'false'",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
		"  windows:",
		"    args_refresh_interval: -1",
		"    add_new_args: true",
		"  scrub_args: true",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err = NewAgentConfig(&ddy)
	assert.NoError(err)
	ep = agentConfig.APIEndpoints[0]
	assert.Equal("apikey_20", ep.APIKey)
	assert.Equal("stackstate.com", ep.Endpoint.Hostname())
	assert.Equal(true, agentConfig.Enabled)
	assert.Equal(false, agentConfig.EnableIncrementalPublishing)
	assert.Equal(2*time.Minute, agentConfig.IncrementalPublishingRefreshInterval)
	assert.Equal(processChecks, agentConfig.EnabledChecks) // sts
	assert.Equal(true, agentConfig.Scrubber.Enabled)

	ddy = YamlAgentConfig{}
	err = yaml.Unmarshal([]byte(strings.Join([]string{
		"sts_url: 'https://stackstate.com'",
		"api_key: apikey_20",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'disabled'",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err = NewAgentConfig(&ddy)
	assert.NoError(err)
	ep = agentConfig.APIEndpoints[0]
	assert.Equal("apikey_20", ep.APIKey)
	assert.Equal("stackstate.com", ep.Endpoint.Hostname())
	assert.Equal(false, agentConfig.Enabled)
	assert.Equal(processChecks, agentConfig.EnabledChecks) // sts
	assert.Equal(true, agentConfig.Scrubber.Enabled)

	ddy = YamlAgentConfig{}
	err = yaml.Unmarshal([]byte(strings.Join([]string{
		"sts_url: 'https://stackstate.com'",
		"api_key: apikey_20",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'disabled'",
		"  additional_endpoints:",
		"    http://localhost:",
		"      - foo",
		"      - bar",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err = NewAgentConfig(&ddy)
	assert.NoError(err)
	eps := agentConfig.APIEndpoints
	assert.Len(agentConfig.APIEndpoints, 3)
	assert.Equal("apikey_20", eps[0].APIKey)
	assert.Equal("stackstate.com", eps[0].Endpoint.Hostname())
	assert.Equal("foo", eps[1].APIKey)
	assert.Equal("localhost", eps[1].Endpoint.Hostname())
	assert.Equal("bar", eps[2].APIKey)
	assert.Equal("localhost", eps[2].Endpoint.Hostname())
	assert.Equal(false, agentConfig.Enabled)
	assert.Equal(processChecks, agentConfig.EnabledChecks) // sts
	assert.Equal(true, agentConfig.Scrubber.Enabled)

	ddy = YamlAgentConfig{}
	site := "datadoghq.eu"
	err = yaml.Unmarshal([]byte(strings.Join([]string{
		"sts_url: 'https://stackstate.com'",
		"api_key: apikey_20",
		"process_agent_enabled: true",
		"site: " + site,
		"process_config:",
		"  enabled: 'true'",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err = NewAgentConfig(&ddy)
	assert.NoError(err)
	assert.Len(agentConfig.APIEndpoints, 1)
	assert.Equal("apikey_20", agentConfig.APIEndpoints[0].APIKey)
	assert.Equal("stackstate.com", agentConfig.APIEndpoints[0].Endpoint.Hostname())
	assert.Equal(true, agentConfig.Enabled)

	ddy = YamlAgentConfig{}
	site = "datacathq.eu"
	err = yaml.Unmarshal([]byte(strings.Join([]string{
		"sts_url: 'https://stackstate.com'",
		"api_key: apikey_20",
		"process_agent_enabled: true",
		"site: " + site,
		"process_config:",
		"  enabled: 'true'",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err = NewAgentConfig(&ddy)
	assert.NoError(err)
	assert.Len(agentConfig.APIEndpoints, 1)
	assert.Equal("apikey_20", agentConfig.APIEndpoints[0].APIKey)
	assert.Equal("stackstate.com", agentConfig.APIEndpoints[0].Endpoint.Hostname())
	assert.Equal(true, agentConfig.Enabled)

}

func TestStackStateNetworkConfigFromMainAgentConfig(t *testing.T) {
	assert := assert.New(t)
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"sts_url: 'https://stackstate.com'",
		"api_key: apikey_20",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'true'",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
		"  network_relation_cache_duration_min: 10",
		"  process_cache_duration_min: 15",
		"  filters:",
		"    short_lived_processes:",
		"      enabled: 'false'",
		"      qualifier_secs: 20",
		"    short_lived_network_relations:",
		"      enabled: true",
		"      qualifier_secs: 30",
		"network_tracer_config:",
		"  network_tracing_enabled: 'true'",
		"  initial_connections_from_proc: 'true'",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(&ddy)
	assert.NoError(err)

	ep := agentConfig.APIEndpoints[0]
	assert.Equal("apikey_20", ep.APIKey)
	assert.Equal("stackstate.com", ep.Endpoint.Hostname())
	assert.Equal(10, agentConfig.QueueSize)
	assert.Equal(true, agentConfig.Enabled)
	assert.Equal(8*time.Second, agentConfig.CheckIntervals["container"])
	assert.Equal(30*time.Second, agentConfig.CheckIntervals["process"])
	assert.Equal(10000, agentConfig.NetworkTracerMaxConnections)
	assert.Equal(append(processChecks, "connections"), agentConfig.EnabledChecks)
	assert.Equal(10*time.Minute, agentConfig.NetworkRelationCacheDurationMin)
	assert.Equal(15*time.Minute, agentConfig.ProcessCacheDurationMin)
	assert.Equal(false, agentConfig.EnableShortLivedProcessFilter)
	assert.Equal(20*time.Second, agentConfig.ShortLivedProcessQualifierSecs)
	assert.Equal(true, agentConfig.EnableShortLivedNetworkRelationFilter)
	assert.Equal(30*time.Second, agentConfig.ShortLivedNetworkRelationQualifierSecs)
}

func TestStackStateNetworkConfigProtocolInspectionDisabled(t *testing.T) {
	assert := assert.New(t)
	var ddy YamlAgentConfig
	err := yaml.Unmarshal(
		[]byte(`
network_tracer_config:
  protocol_inspection_enabled: 'false'
`), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(&ddy)
	assert.NoError(err)

	assert.Equal(false, agentConfig.NetworkTracer.EnableProtocolInspection)
}

func TestStackStateNetworkConfigProtocolsDisabled(t *testing.T) {
	assert := assert.New(t)
	var ddy YamlAgentConfig
	err := yaml.Unmarshal(
		[]byte(`
network_tracer_config:
  disabled_protocols: ['amqp']
`), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(&ddy)
	assert.NoError(err)

	assert.Equal(true, slices.Contains(agentConfig.NetworkTracer.DisabledProtocols, AMQPProtocolName))
}

func TestStackStateHttpTracingDisabled(t *testing.T) {
	assert := assert.New(t)
	var ddy YamlAgentConfig
	err := yaml.Unmarshal(
		[]byte(`
network_tracer_config:
  http_tracing_enabled: 'true'
`), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(&ddy)
	assert.NoError(err)

	assert.Equal(true, agentConfig.NetworkTracer.EnableHTTPTracing)
}

func TestStackStateMaxHttpStatsBufferPresent(t *testing.T) {
	assert := assert.New(t)
	var ddy YamlAgentConfig
	err := yaml.Unmarshal(
		[]byte(`
network_tracer_config:
  http_stats_buffer_size: 200000
`), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(&ddy)
	assert.NoError(err)

	assert.Equal(200000, agentConfig.NetworkTracer.MaxHTTPStatsBuffered)
}

func TestStackStateMaxHttpStatsBufferAbsent(t *testing.T) {
	assert := assert.New(t)
	var ddy YamlAgentConfig
	err := yaml.Unmarshal(
		[]byte(`
network_tracer_config:
  protocol_inspection_enabled: 'false'
`), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(&ddy)
	assert.NoError(err)

	assert.Equal(100000, agentConfig.NetworkTracer.MaxHTTPStatsBuffered)
}

func TestStackStateMaxHttpObservationsBufferPresent(t *testing.T) {
	assert := assert.New(t)
	var ddy YamlAgentConfig
	err := yaml.Unmarshal(
		[]byte(`
network_tracer_config:
  http_observations_buffer_size: 200000
`), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(&ddy)
	assert.NoError(err)

	assert.Equal(200000, agentConfig.NetworkTracer.MaxHTTPObservationsBuffered)
}

func TestStackStateMaxHttpObservationsBufferAbsent(t *testing.T) {
	assert := assert.New(t)
	var ddy YamlAgentConfig
	err := yaml.Unmarshal(
		[]byte(`
network_tracer_config:
  protocol_inspection_enabled: 'false'
`), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(&ddy)
	assert.NoError(err)

	assert.Equal(100000, agentConfig.NetworkTracer.MaxHTTPObservationsBuffered)
}

func TestEnvOverrides(t *testing.T) {
	assert := assert.New(t)
	os.Setenv("STS_NETWORK_TRACER_MAX_CONNECTIONS", "500")
	os.Setenv("STS_CLUSTER_NAME", "test-override")
	os.Setenv("STS_MAX_PROCESSES_PER_MESSAGE", "501")
	os.Setenv("STS_MAX_CONNECTIONS_PER_MESSAGE", "502")
	os.Setenv("STS_PROTOCOL_INSPECTION_ENABLED", "false")
	os.Setenv("STS_NETWORK_TRACING_ENABLED", "true")
	os.Setenv("STS_HTTP_TRACING_ENABLED", "true")
	os.Setenv("STS_HTTP_STATS_BUFFER_SIZE", "150000")
	os.Setenv("STS_HTTP_OBSERVATIONS_BUFFER_SIZE", "160000")
	os.Setenv("STS_DISABLED_PROTOCOLS", "AMQP,hTTp")

	agentConfig, _ := NewAgentConfig(nil)

	assert.Equal(500, agentConfig.NetworkTracerMaxConnections)
	assert.Equal(501, agentConfig.MaxPerMessage)
	assert.Equal(502, agentConfig.MaxConnectionsPerMessage)
	assert.Equal(false, agentConfig.NetworkTracer.EnableProtocolInspection)
	assert.Equal(true, agentConfig.EnableNetworkTracing)
	assert.Equal(true, agentConfig.NetworkTracer.EnableHTTPTracing)
	assert.Equal(150000, agentConfig.NetworkTracer.MaxHTTPStatsBuffered)
	assert.Equal(160000, agentConfig.NetworkTracer.MaxHTTPObservationsBuffered)
	assert.Equal(true, slices.Contains(agentConfig.NetworkTracer.DisabledProtocols, AMQPProtocolName))
	assert.Equal(true, slices.Contains(agentConfig.NetworkTracer.DisabledProtocols, HTTPProtocolName))
}

func TestEnvSiteConfig(t *testing.T) {
	assert := assert.New(t)
	for _, tc := range []struct {
		stsURL   string
		expected string
	}{
		{
			"http://localhost",
			"localhost",
		},
		{
			"https://burrito.com",
			"burrito.com",
		},
	} {
		// Fake the os.Setenv("STS_SITE", tc.site)
		os.Setenv("STS_PROCESS_AGENT_URL", tc.stsURL)

		agentConfig, err := NewAgentConfig(&YamlAgentConfig{})
		assert.NoError(err)
		assert.Equal(tc.expected, agentConfig.APIEndpoints[0].Endpoint.Hostname())
	}
}

func TestIsAffirmative(t *testing.T) {
	value, err := isAffirmative("yes")
	assert.Nil(t, err)
	assert.True(t, value)

	value, err = isAffirmative("True")
	assert.Nil(t, err)
	assert.True(t, value)

	value, err = isAffirmative("1")
	assert.Nil(t, err)
	assert.True(t, value)

	_, err = isAffirmative("")
	assert.NotNil(t, err)

	value, err = isAffirmative("ok")
	assert.Nil(t, err)
	assert.False(t, value)
}

func TestStackStateFallbackAgentConfigToSTSUrl(t *testing.T) {
	assert := assert.New(t)
	os.Unsetenv("STS_PROCESS_AGENT_URL")
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_30",
		"sts_url: http://default-endpoint.test.stackstate.com",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'true'",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
		"network_tracer_config:",
		"  network_tracing_enabled: 'true'",
		"  initial_connections_from_proc: 'true'",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(&ddy)
	assert.NoError(err)

	ep := agentConfig.APIEndpoints[0]
	assert.Equal("apikey_30", ep.APIKey)
	assert.Equal("default-endpoint.test.stackstate.com", ep.Endpoint.Hostname())
}

func TestStackStateFallbackAgentConfigToEnvSTSUrl(t *testing.T) {
	assert := assert.New(t)
	os.Unsetenv("STS_PROCESS_AGENT_URL")
	os.Unsetenv("STS_STS_URL")
	os.Setenv("STS_STS_URL", "http://default-endpoint.test.stackstate.com")
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_30",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'true'",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
		"network_tracer_config:",
		"  network_tracing_enabled: 'true'",
		"  initial_connections_from_proc: 'true'",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(&ddy)
	assert.NoError(err)

	ep := agentConfig.APIEndpoints[0]
	assert.Equal("apikey_30", ep.APIKey)
	assert.Equal("default-endpoint.test.stackstate.com", ep.Endpoint.Hostname())
}

func TestStackStateFallbackAgentConfigEmptyUrlToEnvSTSUrl(t *testing.T) {
	assert := assert.New(t)
	os.Unsetenv("STS_PROCESS_AGENT_URL")
	os.Unsetenv("STS_STS_URL")
	os.Setenv("STS_STS_URL", "http://default-endpoint.test.stackstate.com")
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_30",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'true'",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
		"network_tracer_config:",
		"  network_tracing_enabled: 'true'",
		"  initial_connections_from_proc: 'true'",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(&ddy)
	assert.NoError(err)

	ep := agentConfig.APIEndpoints[0]
	assert.Equal("apikey_30", ep.APIKey)
	assert.Equal("default-endpoint.test.stackstate.com", ep.Endpoint.Hostname())
}

// case 5: STS_URL as env	PROCESS_AGENT_URL as env
func TestStackStatePreferAgentConfigToEnvPROCESS_AGENT_URL(t *testing.T) {
	assert := assert.New(t)
	os.Unsetenv("STS_PROCESS_AGENT_URL")
	os.Unsetenv("STS_STS_URL")
	os.Setenv("STS_STS_URL", "http://default-endpoint.test.stackstate.com")
	os.Setenv("STS_PROCESS_AGENT_URL", "http://process-endpoint.test.stackstate.com")
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_30",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'true'",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
		"network_tracer_config:",
		"  network_tracing_enabled: 'true'",
		"  initial_connections_from_proc: 'true'",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(&ddy)
	assert.NoError(err)

	ep := agentConfig.APIEndpoints[0]
	assert.Equal("apikey_30", ep.APIKey)
	assert.Equal("process-endpoint.test.stackstate.com", ep.Endpoint.Hostname())
}

// case 7: STS_URL as env	PROCESS_AGENT_URL as yaml - STS URL wins, more specific
func TestStackStatePreferSTS_STS_URLOverYamlProcessAgentConfig(t *testing.T) {
	assert := assert.New(t)
	os.Unsetenv("STS_PROCESS_AGENT_URL")
	os.Unsetenv("STS_STS_URL")
	os.Setenv("STS_STS_URL", "http://default-endpoint.test.stackstate.com")
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_30",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'true'",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
		"network_tracer_config:",
		"  network_tracing_enabled: 'true'",
		"  initial_connections_from_proc: 'true'",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(&ddy)
	assert.NoError(err)

	ep := agentConfig.APIEndpoints[0]
	assert.Equal("apikey_30", ep.APIKey)
	assert.Equal("default-endpoint.test.stackstate.com", ep.Endpoint.Hostname())
}

// case 8: STS_URL as yaml, PROCESS_AGENT_URL as env - ENV wins
func TestStackStatePreferPROCESS_AGENT_URLOverYamlsts_sts_url(t *testing.T) {
	assert := assert.New(t)
	os.Unsetenv("STS_PROCESS_AGENT_URL")
	os.Unsetenv("STS_STS_URL")
	os.Setenv("STS_PROCESS_AGENT_URL", "http://process-endpoint.test.stackstate.com")
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_30",
		"sts_url: http://default-endpoint.test.stackstate.com",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'true'",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
		"network_tracer_config:",
		"  network_tracing_enabled: 'true'",
		"  initial_connections_from_proc: 'true'",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(&ddy)
	assert.NoError(err)

	ep := agentConfig.APIEndpoints[0]
	assert.Equal("apikey_30", ep.APIKey)
	assert.Equal("process-endpoint.test.stackstate.com", ep.Endpoint.Hostname())
}

func TestNetworkTracerInitRetry_FromYaml(t *testing.T) {
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"network_tracer_config:",
		"  network_tracer_retry_init_duration_sec: 50",
		"  network_tracer_retry_init_amount: 10",
	}, "\n")), &ddy)
	assert.NoError(t, err)

	agentConfig, err := NewAgentConfig(&ddy)
	assert.NoError(t, err)

	assert.Equal(t, 10, agentConfig.NetworkTracerInitRetryAmount)
	assert.Equal(t, 50*time.Second, agentConfig.NetworkTracerInitRetryDuration)
}

func TestCheckIntervalCodeDefaults(t *testing.T) {
	agentConfig, err := NewAgentConfig(nil)
	assert.NoError(t, err)

	assert.Equal(t, time.Duration(30)*time.Second, agentConfig.CheckIntervals["process"])
	assert.Equal(t, time.Duration(30)*time.Second, agentConfig.CheckIntervals["connections"])
}

func TestCheckIntervalCodeDefaults_FromYaml(t *testing.T) {
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"process_config:",
		"  intervals:",
		"    container: 10",
		"    process: 10",
		"    connections: 10",
	}, "\n")), &ddy)
	assert.NoError(t, err)

	agentConfig, err := NewAgentConfig(&ddy)
	assert.NoError(t, err)

	assert.Equal(t, time.Duration(10)*time.Second, agentConfig.CheckIntervals["container"])
	assert.Equal(t, time.Duration(10)*time.Second, agentConfig.CheckIntervals["process"])
	assert.Equal(t, time.Duration(10)*time.Second, agentConfig.CheckIntervals["connections"])
}

func TestCheckIntervalCodeDefaults_FromEnv(t *testing.T) {
	os.Setenv("STS_CONTAINER_CHECK_INTERVAL", "15")
	os.Setenv("STS_PROCESS_CHECK_INTERVAL", "15")
	os.Setenv("STS_CONNECTION_CHECK_INTERVAL", "15")

	agentConfig, err := NewAgentConfig(nil)
	assert.NoError(t, err)

	assert.Equal(t, time.Duration(15)*time.Second, agentConfig.CheckIntervals["container"])
	assert.Equal(t, time.Duration(15)*time.Second, agentConfig.CheckIntervals["process"])
	assert.Equal(t, time.Duration(15)*time.Second, agentConfig.CheckIntervals["connections"])
}

func TestCheckIntervalCodeDefaults_FromEnvOverridesYaml(t *testing.T) {
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"process_config:",
		"  intervals:",
		"    process: 10",
		"    connections: 10",
	}, "\n")), &ddy)
	assert.NoError(t, err)

	os.Setenv("STS_CONTAINER_CHECK_INTERVAL", "20")
	os.Setenv("STS_PROCESS_CHECK_INTERVAL", "20")
	os.Setenv("STS_CONNECTION_CHECK_INTERVAL", "20")

	agentConfig, err := NewAgentConfig(&ddy)
	assert.NoError(t, err)

	assert.Equal(t, time.Duration(20)*time.Second, agentConfig.CheckIntervals["process"])
	assert.Equal(t, time.Duration(20)*time.Second, agentConfig.CheckIntervals["connections"])
}

func TestSkipSSLValidation_Default(t *testing.T) {
	var ddy YamlAgentConfig
	conf, err := NewAgentConfig(&ddy)
	assert.NoError(t, err)

	assert.Equal(t, false, conf.SkipSSLValidation)
}

func TestSkipSSLValidation_FromYaml(t *testing.T) {
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"skip_ssl_validation: true",
	}, "\n")), &ddy)
	assert.NoError(t, err)

	conf, err := NewAgentConfig(&ddy)
	assert.NoError(t, err)

	assert.Equal(t, true, conf.SkipSSLValidation)
}

func TestSkipSSLValidation_FromEnv(t *testing.T) {
	os.Setenv("STS_SKIP_SSL_VALIDATION", "true")

	conf, err := NewAgentConfig(nil)
	assert.NoError(t, err)

	assert.Equal(t, true, conf.SkipSSLValidation)

	os.Unsetenv("STS_SKIP_SSL_VALIDATION")
}

func TestSkipKubeletTLSVerify_Default(t *testing.T) {
	var ddy YamlAgentConfig
	conf, err := NewAgentConfig(&ddy)
	assert.NoError(t, err)

	assert.Equal(t, false, conf.SkipKubeletTLSVerify)
}

func TestSkipKubeletTLSVerify_FromYaml(t *testing.T) {
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"skip_kubelet_tls_verify: true",
	}, "\n")), &ddy)
	assert.NoError(t, err)

	conf, err := NewAgentConfig(&ddy)
	assert.NoError(t, err)

	assert.Equal(t, true, conf.SkipKubeletTLSVerify)
}

func TestSkipKubeletTLSVerify_FromEnv(t *testing.T) {
	os.Setenv("STS_SKIP_KUBELET_TLS_VERIFY", "true")

	conf, err := NewAgentConfig(nil)
	assert.NoError(t, err)

	assert.Equal(t, true, conf.SkipKubeletTLSVerify)

	os.Unsetenv("STS_SKIP_KUBELET_TLS_VERIFY")
}

func TestHTTPStatsPerPath_FromEnv(t *testing.T) {
	os.Setenv("STS_HTTP_STATS_PER_PATH", "true")

	conf, err := NewAgentConfig(nil)
	assert.NoError(t, err)

	assert.Equal(t, true, conf.HTTPStatsPerPath)

	os.Unsetenv("STS_HTTP_STATS_PER_PATH")
}
