// +build linux

package net

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"context"
	"net"

	"github.com/StackVista/stackstate-agent/pkg/util/log"
	"github.com/StackVista/stackstate-agent/pkg/util/retry"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
)

const (
	statusURL      = "http://unix/status"
	connectionsURL = "http://unix/connections"
)

var (
	globalUtil            *RemoteNetTracerUtil
	globalSocketPath      string
	hasLoggedErrForStatus map[retry.Status]struct{}
)

func init() {
	hasLoggedErrForStatus = make(map[retry.Status]struct{})
}

// RemoteNetTracerUtil wraps interactions with a remote network tracer service
type RemoteNetTracerUtil struct {
	// Retrier used to setup network tracer
	initRetry retry.Retrier

	socketPath string
	httpClient http.Client
}

// SetNetworkTracerSocketPath provides a unix socket path location to be used by the remote network tracer.
// This needs to be called before GetRemoteNetworkTracerUtil.
func SetNetworkTracerSocketPath(socketPath string) {
	globalSocketPath = socketPath
}

// GetRemoteNetworkTracerUtil returns a ready to use RemoteNetTracerUtil. It is backed by a shared singleton.
func GetRemoteNetworkTracerUtil() (*RemoteNetTracerUtil, error) {
	if globalSocketPath == "" {
		return nil, fmt.Errorf("remote tracer has no socket path defined")
	}

	if globalUtil == nil {
		globalUtil = newNetworkTracer()
		globalUtil.initRetry.SetupRetrier(&retry.Config{
			Name:          "network-tracer-util",
			AttemptMethod: globalUtil.init,
			Strategy:      retry.RetryCount,
			// 10 tries w/ 30s delays = 5m of trying before permafail
			RetryCount: 10,
			RetryDelay: 30 * time.Second,
		})
	}

	if err := globalUtil.initRetry.TriggerRetry(); err != nil {
		log.Debugf("network tracer init error: %s", err)
		return nil, err
	}

	return globalUtil, nil
}

// GetConnections returns a set of active network connections, retrieved from the network tracer service
func (r *RemoteNetTracerUtil) GetConnections() ([]common.ConnectionStats, error) {
	// Otherwise, get it remotely (via unix socket), and parse from JSON
	resp, err := r.httpClient.Get(connectionsURL)
	if err != nil {
		return nil, err
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("conn request failed: socket %s, url: %s, status code: %d", r.socketPath, connectionsURL, resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	conn := &common.Connections{}
	if err := conn.UnmarshalJSON(body); err != nil {
		return nil, err
	}

	return conn.Conns, nil
}

// ShouldLogTracerUtilError will return whether or not errors sourced from the RemoteNetTracerUtil _should_ be logged, for less noisy logging.
// We only want to log errors if the tracer has been initialized, or it's the first error for a particular tracer status
// (e.g. retrying, permafail)
func ShouldLogTracerUtilError() bool {
	status := globalUtil.initRetry.RetryStatus()

	_, logged := hasLoggedErrForStatus[status]
	hasLoggedErrForStatus[status] = struct{}{}

	return status == retry.OK || !logged
}

func newNetworkTracer() *RemoteNetTracerUtil {
	return &RemoteNetTracerUtil{
		socketPath: globalSocketPath,
		httpClient: http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:    2,
				IdleConnTimeout: 30 * time.Second,
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", globalSocketPath)
				},
				TLSHandshakeTimeout:   1 * time.Second,
				ResponseHeaderTimeout: 5 * time.Second,
				ExpectContinueTimeout: 50 * time.Millisecond,
			},
		},
	}
}

func (r *RemoteNetTracerUtil) init() error {
	if resp, err := r.httpClient.Get(statusURL); err != nil {
		return err
	} else if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("remote tracer status check failed: socket %s, url: %s, status code: %d", r.socketPath, statusURL, resp.StatusCode)
	}
	return nil
}
