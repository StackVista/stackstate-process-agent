//go:build !windows
// +build !windows

package main

import (
	"flag"
	_ "net/http/pprof"

	"github.com/StackVista/stackstate-process-agent/config"
)

func main() {
	flag.StringVar(&opts.configPath, "config", "/etc/stackstate-agent/stackstate.yaml", "Path to stackstate.yaml config")
	flag.StringVar(&opts.pidfilePath, "pid", "", "Path to set pidfile for process")
	flag.BoolVar(&opts.info, "info", false, "Show info about running process agent and exit")
	flag.BoolVar(&opts.version, "version", false, "Print the version and exit")
	flag.StringVar(&opts.check, "check", "", "Run a specific check and print the results. Choose from: process, connections, realtime")
	flag.Parse()

	// Set up a default config before parsing config so we log errors nicely.
	// The default will be stdout since we can't assume any file is writeable.
	if err := config.NewLoggerLevel("info", "", true); err != nil {
		panic(err)
	}

	exit := make(chan bool)

	// Invoke the Agent
	runAgent(exit)
}
