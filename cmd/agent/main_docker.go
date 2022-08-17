//go:build docker
// +build docker

package main

import (
	"os"
	"os/signal"
	"syscall"

	_ "github.com/StackVista/stackstate-agent/pkg/util/containers/providers/cgroup"
	log "github.com/cihub/seelog"
)

// HandleSignals tells us whether we should exit.
func HandleSignals(exit chan bool) {
	sigIn := make(chan os.Signal, 100)
	signal.Notify(sigIn, syscall.SIGINT, syscall.SIGTERM, syscall.SIGPIPE)
	// unix only in all likelihood; but we don't care.
	for sig := range sigIn {
		switch sig {
		case syscall.SIGINT, syscall.SIGTERM:
			log.Infof("Caught signal '%s'; terminating.", sig)
			exit <- true
			return
		case syscall.SIGPIPE:
			// By default systemd redirects the stdout to journald. When journald is stopped or crashes we receive a SIGPIPE signal.
			// Go ignores SIGPIPE signals unless it is when stderr or stdout is closed, in this case the agent is stopped.
			// We never want the agent to stop upon receiving SIGPIPE, so we intercept the SIGPIPE signals and just discard them.
			// See https://golang.org/pkg/os/signal/#hdr-SIGPIPE
			continue
		}
	}
}
