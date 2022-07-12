package main

import (
	"github.com/StackVista/agent-transport-protocol/pkg/model"
	"github.com/StackVista/agent-transport-protocol/pkg/transport/nats"
	log "github.com/cihub/seelog"
)

// NatsSender holds the NATS client and the map of chan for all subjects
type NatsSender struct {
	Enabled bool
	client  *nats.Client
	chMap   map[string]chan *model.MessageBody
}

// CreateNatsSender creates a new NatsSender object
func CreateNatsSender() NatsSender {
	client := nats.NewNATSClient()
	if _, err := client.Connect(); err != nil {
		_ = log.Errorf("Failed to connect to NATS: %s", err)
		return NatsSender{Enabled: false}
	}
	log.Infof("Connected to NATS server on ", client.ServerURL)
	chMap := make(map[string]chan *model.MessageBody)
	return NatsSender{
		Enabled: true,
		client:  client,
		chMap:   chMap,
	}
}

// BindSubject creates a new chan, binds to the parameter subject and add to the map of chan
func (c *NatsSender) BindSubject(subject string) error {
	sendNatsCh := make(chan *model.MessageBody)
	err := c.client.BindSendChan(subject, sendNatsCh)
	if err != nil {
		return err
	}
	c.chMap[subject] = sendNatsCh
	log.Infof("Bound chan '%v' for NATS subject '%s'", sendNatsCh, subject)
	return nil
}

// GetSubjectChan returns the channel bound to the parameter subject
func (c *NatsSender) GetSubjectChan(subject string) (chan *model.MessageBody, bool) {
	log.Infof("Getting chan for NATS subject '%s'", subject)
	ch, ok := c.chMap[subject]
	log.Infof("Got chan '%v' for NATS subject '%s'", ch, subject)
	return ch, ok
}

// Close closes the connection to the NATS client
func (c *NatsSender) Close() {
	c.client.Close()
}
