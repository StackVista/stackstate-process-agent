package tracer

import (
	"github.com/StackVista/stackstate-process-agent/pkg/tracer/config"
)

const CheckMessageSize = false

func MakeTestConfig() *config.Config {
	c := config.MakeDefaultConfig()
	return c
}
