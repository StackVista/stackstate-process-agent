package main

import "encoding/json"

// PatternConfig represents the configuration for a test pattern.
type PatternConfig struct {
	Name   string          `json:"name"`
	Schema json.RawMessage `json:"schema"`
}

// Config represents the configuration for the test server.
type Config struct {
	Server struct {
		Host string `json:"host"`
		Port string `json:"port"`
	} `json:"server"`
	LogLevel     string          `json:"log_level"`
	OutputFile   string          `json:"output_file"`
	RequestCount int             `json:"request_count"`
	Patterns     []PatternConfig `json:"patterns"`
}
