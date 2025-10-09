package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/StackVista/stackstate-process-agent/checks"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/stretchr/testify/assert"
)

func TestHealthStateMessageCut(t *testing.T) {
	assert := assert.New(t)
	cfg := config.NewDefaultAgentConfig()
	// Enable only the process check to avoid injection of ebpf stuff with the connnections check
	cfg.EnabledChecks = []string{config.ProcessCheckName}
	c, err := NewCollector(cfg, nil, nil, nil)
	assert.NoError(err)

	_, checkData := c.makeHealth(checkResult{
		check:   &checks.ProcessCheck{},
		err:     errors.New(strings.Repeat("X", cfg.CheckHealthStateMessageLimit*2)),
		payload: nil,
	})

	assert.Len(checkData.CheckState.Message, cfg.CheckHealthStateMessageLimit)
}
