//go:build !docker
// +build !docker

package main

import (
	"os"
	"os/signal"
	"syscall"

	log "github.com/cihub/seelog"
)

// Handles signals - tells us whether we should exit.
func handleSignals(exit chan bool) {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		// Set up the signals async so we can Start the agent
		select {
		case sig := <-signalCh:
			log.Infof("Received signal '%s', shutting down...", sig)
			signalCh <- nil
			exit <- true
		default:
			// continue
		}
	}()

	// By default systemd redirects the stdout to journald. When journald is stopped or crashes we receive a SIGPIPE signal.
	// Go ignores SIGPIPE signals unless it is when stdout or stdout is closed, in this case the agent is stopped.
	// We never want the agent to stop upon receiving SIGPIPE, so we intercept the SIGPIPE signals and just discard them.
	sigpipeCh := make(chan os.Signal, 1)
	signal.Notify(sigpipeCh, syscall.SIGPIPE)
	go func() {
		for range sigpipeCh {
			// do nothing
		}
	}()

}
