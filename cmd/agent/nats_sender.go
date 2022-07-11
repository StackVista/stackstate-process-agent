package main

import (
	"github.com/StackVista/agent-transport-protocol/pkg/model"
	"github.com/StackVista/agent-transport-protocol/pkg/transport/nats"
	log "github.com/cihub/seelog"
)

type INatsSender interface {
	BindSubject(subject string) error
	GetSubjectChan(subject string) (chan *model.Message, bool)
	Close()
}

type NatsSender struct {
	Enabled bool
	client  *nats.Client
	chMap   map[string]chan *model.Message
}

func CreateNatsSender() NatsSender {
	client := nats.NewNATSClient()
	if _, err := client.Connect(); err != nil {
		_ = log.Errorf("Failed to connect to NATS: %s", err)
		return NatsSender{Enabled: false}
	}
	chMap := make(map[string]chan *model.Message)
	return NatsSender{
		Enabled: true,
		client:  client,
		chMap:   chMap,
	}
}

func (c *NatsSender) BindSubject(subject string) error {
	sendNatsCh := make(chan *model.Message)
	err := c.client.BindSendChan(subject, sendNatsCh)
	if err != nil {
		return err
	}
	c.chMap[subject] = sendNatsCh
	return nil
}

func (c *NatsSender) GetSubjectChan(subject string) (chan *model.Message, bool) {
	ch, ok := c.chMap[subject]
	return ch, ok
}

func (c *NatsSender) Close() {
	c.client.Close()
}
