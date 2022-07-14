package nats

import (
	"fmt"
	"github.com/StackVista/agent-transport-protocol/pkg/model"
	"github.com/StackVista/agent-transport-protocol/pkg/transport/nats"
	log "github.com/cihub/seelog"
)

// Sender holds the NATS client and the map of chan for all subjects
type Sender struct {
	Enabled bool
	client  *nats.Client
	chMap   map[string]chan *model.MessageBody
}

// CreateNatsSender creates a new Sender object
func CreateNatsSender() Sender {
	client := nats.NewNATSClient()
	if _, err := client.Connect(); err != nil {
		_ = log.Errorf("Failed to connect to NATS: %s", err)
		return Sender{Enabled: false}
	}
	log.Infof("Connected to NATS server on ", client.ServerURL)
	chMap := make(map[string]chan *model.MessageBody)
	return Sender{
		Enabled: true,
		client:  client,
		chMap:   chMap,
	}
}

// SendMessage sends a message
func (s *Sender) SendMessage(subject string, encodedMessage []byte) error {
	err := s.client.Conn.Publish(subject, encodedMessage)
	if err != nil {
		return fmt.Errorf("could not send message to NATS. Error: %v", err)
	}
	return nil
}

// Close closes the connection to the NATS client
func (s *Sender) Close() {
	s.client.Close()
}
