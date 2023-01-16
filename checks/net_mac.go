//go:build darwin
// +build darwin

package checks

import (
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
)

// Init initializes a ConnectionsCheck instance.
func (c *ConnectionsCheck) Init(cfg *config.AgentConfig, sysInfo *model.SystemInfo) {

}
