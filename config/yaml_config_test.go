package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewYamlIfExists(t *testing.T) {
	for _, tc := range []struct {
		name       string
		input      string
		scrubArgs  *bool
		addNewArgs *bool
	}{
		{name: "omitted", scrubArgs: boolPointer(true), addNewArgs: boolPointer(true)},
		{name: "false", input: "process_config:\n  scrub_args: false\n  windows:\n    add_new_args: false\n", scrubArgs: boolPointer(false), addNewArgs: boolPointer(false)},
		{name: "null", input: "process_config:\n  scrub_args: null\n  windows:\n    add_new_args: null\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "process.yaml")
			require.NoError(t, os.WriteFile(path, []byte(tc.input), 0600))
			conf, err := NewYamlIfExists(path)
			require.NoError(t, err)
			require.NotNil(t, conf)
			assert.Equal(t, tc.scrubArgs, conf.Process.ScrubArgs)
			assert.Equal(t, tc.addNewArgs, conf.Process.Windows.AddNewArgs)
		})
	}
}

func TestNewYamlIfExistsV2ScalarsAndAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "process.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`api_key: &key sample-key
sts_url: https://example.com
skip_ssl_validation: yes
unknown_setting: ignored
process_config:
  intervals:
    process: 010
    connections: 0x10
  process_blacklist:
    patterns:
      - |-
        first
        second
  additional_endpoints:
    https://additional.example.com: [*key]
network_tracer_config:
  network_tracing_enabled: on
  disabled_protocols: [http, postgres]
`), 0600))

	conf, err := NewYamlIfExists(path)
	require.NoError(t, err)
	require.NotNil(t, conf)
	assert.Equal(t, "sample-key", conf.APIKey)
	assert.Equal(t, "https://example.com", conf.StsURL)
	assert.True(t, conf.SkipSSLValidation)
	assert.Equal(t, 8, conf.Process.Intervals.Process)
	assert.Equal(t, 16, conf.Process.Intervals.Connections)
	assert.Equal(t, []string{"first\nsecond"}, conf.Process.Blacklist.Patterns)
	assert.Equal(t, map[string][]string{"https://additional.example.com": {"sample-key"}}, conf.Process.AdditionalEndpoints)
	assert.Equal(t, "on", conf.Network.NetworkTracingEnabled)
	assert.Equal(t, []string{"http", "postgres"}, conf.Network.DisabledProtocols)
}

func TestNewYamlIfExistsMissingAndInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "process.yaml")
	conf, err := NewYamlIfExists(path)
	require.NoError(t, err)
	assert.Nil(t, conf)

	require.NoError(t, os.WriteFile(path, []byte("process_config: ["), 0600))
	conf, err = NewYamlIfExists(path)
	require.ErrorContains(t, err, "parse error:")
	assert.Nil(t, conf)
}

func boolPointer(value bool) *bool {
	return &value
}
