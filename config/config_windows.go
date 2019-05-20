// +build windows

package config

import (
	"path/filepath"

	"github.com/StackVista/stackstate-agent/pkg/util/executable"
	"github.com/StackVista/stackstate-agent/pkg/util/winutil"
)

var (
	defaultLogFilePath = "c:\\programdata\\datadog\\logs\\process-agent.log"

	// Agent 6
	defaultDDAgentBin = "c:\\Program Files\\Datadog\\Datadog Agent\\embedded\\agent.exe"
)

func init() {
	if pd, err := winutil.GetProgramDataDir(); err == nil {
		defaultLogFilePath = filepath.Join(pd, "logs", "process-agent.log")
	}
	if _here, err := executable.Folder(); err == nil {
		defaultDDAgentBin = filepath.Join(_here, "..", "..", "embedded", "agent.exe")
	}

}
