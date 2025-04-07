package main

import (
	"fmt"

	"github.com/StackVista/stackstate-receiver-go-client/pkg/model/health"
)

func (l *Collector) agentID() string {
	return fmt.Sprintf("urn:host:/%s", l.cfg.HostName)
}

func (l *Collector) healthStreamURN(checkName string) string {
	return fmt.Sprintf("urn:health:stackstate-process-agent:%s_check", checkName)
}

func (l *Collector) makeHealth(result checkResult) (health.Stream, health.CheckData) {
	checkData := health.CheckData{
		CheckState: &health.CheckState{
			CheckStateID:              l.agentID(),
			TopologyElementIdentifier: l.agentID(),
			Health:                    health.Clear,
			Name:                      fmt.Sprintf("Process Agent - %s gathering", result.check.Name()),
		},
	}
	if result.err != nil {
		checkData.CheckState.Health = health.Deviating
		checkData.CheckState.Message = fmt.Sprintf("Check failed:\n```\n%v\n```", result.err)
		checkData.CheckState.Message = stripMessage(
			checkData.CheckState.Message, l.cfg.CheckHealthStateMessageLimit,
			"[...message was cut to fit...]")
	}

	stream := health.Stream{
		Urn:       l.healthStreamURN(result.check.Name()),
		SubStream: l.agentID(),
	}

	return stream, checkData
}

func stripMessage(message string, maxSize int, replacement string) string {
	if len(message) <= maxSize {
		return message
	}
	if maxSize <= len(replacement) {
		return message
	}

	toKeep := maxSize - len(replacement)
	toKeepRight := toKeep / 2
	toKeepLeft := toKeep - toKeepRight

	return message[0:toKeepLeft] + replacement + message[(len(message)-toKeepRight):]
}
