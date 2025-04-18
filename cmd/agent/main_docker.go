//go:build docker
// +build docker

package main

import (
	"os"
	"os/signal"
	"sync"
	"syscall"

	log "github.com/cihub/seelog"
)

var thrownSignalWarnings sync.Map

// Handles signals - tells us whether we should exit.
func handleSignals(exit chan bool) {
	sigIn := make(chan os.Signal, 100)
	signal.Notify(sigIn)
	// unix only in all likelihood;  but we don't care.
	for sig := range sigIn {
		switch sig {
		case syscall.SIGINT, syscall.SIGTERM:
			log.Criticalf("Caught signal '%s'; terminating.", sig)
			close(exit)
		case syscall.SIGCHLD:
			// Running docker.GetDockerStat() spins up / kills a new process
			continue
		default:
			if _, exists := thrownSignalWarnings.LoadOrStore(sig, true); !exists {
				log.Infof("Caught signal %s; continuing/ignoring.", sig)
			}
		}
	}
}
