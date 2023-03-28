package main

import (
	"errors"
	"github.com/StackVista/stackstate-process-agent/checks"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestHealthStateMessageCut(t *testing.T) {
	assert := assert.New(t)
	cfg := config.NewDefaultAgentConfig()
	c, err := NewCollector(cfg, nil, nil, nil)
	assert.NoError(err)

	_, checkData := c.makeHealth(checkResult{
		check:   &checks.ProcessCheck{},
		err:     errors.New(strings.Repeat("X", cfg.CheckHealthStateMessageLimit*2)),
		payload: nil,
	})

	assert.Len(checkData.CheckState.Message, cfg.CheckHealthStateMessageLimit)
}
