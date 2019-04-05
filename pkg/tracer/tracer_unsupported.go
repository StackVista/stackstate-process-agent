// +build !linux_bpf,!windows

package tracer

import (
	"github.com/StackVista/stackstate-process-agent/pkg/tracer/common"
	"github.com/StackVista/stackstate-process-agent/pkg/tracer/config"
)

type UnsupportedTracer struct{}

func MakeTracer(config *config.Config) (Tracer, error) {
	return &UnsupportedTracer{}, common.ErrNotImplemented
}

func CheckTracerSupport() (bool, error) {
	return false, common.ErrNotImplemented
}

func (t *UnsupportedTracer) Start() error {
	return common.ErrNotImplemented
}

func (t *UnsupportedTracer) Stop() {}

func (t *UnsupportedTracer) GetConnections() (*common.Connections, error) {
	return nil, common.ErrNotImplemented
}