package tracer

import (
	"github.com/StackVista/stackstate-process-agent/pkg/tracer/common"
	"github.com/StackVista/stackstate-process-agent/pkg/tracer/config"
)

type Tracer interface {
	Start() error
	Stop()
	GetConnections() (*common.Connections, error)
}

// Generic New Tracer function
func NewTracer(config *config.Config) (Tracer, error) {
	// Ensures that each tracer implements a MakeTracer function
	return MakeTracer(config)
}
// Generic IsSupported function
func IsTracerSupportedByOS() (bool, error) {
	// Ensures that each tracer implements a CheckTracerSupport function
	return CheckTracerSupport()
}
