package model

import (
	"encoding/base64"
	"testing"

	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

func TestEncodeZeroTimestamp(t *testing.T) {
	header := MessageHeader{
		Version:        MessageV3,
		Encoding:       MessageEncodingZstdPB,
		Type:           TypeCollectorProc,
		SubscriptionID: 0,
		OrgID:          0,
		Timestamp:      0,
	}
	headerBytes, err := encodeHeader(header)
	assert.NoError(t, err)
	headerB64 := base64.StdEncoding.EncodeToString(headerBytes)

	// the same values are expected in the StackState receiver
	// make sure of backward compatibility when changing it
	assert.EqualValues(t, "AwIMAAAAAAAAAAAAAAAAAA==", headerB64)
}

func TestEncodeNonZeroTimestamp(t *testing.T) {
	header := MessageHeader{
		Version:        MessageV3,
		Encoding:       MessageEncodingZstdPB,
		Type:           TypeCollectorProc,
		SubscriptionID: 0,
		OrgID:          0,
		Timestamp:      1638527655412,
	}
	headerBytes, err := encodeHeader(header)
	assert.NoError(t, err)
	headerB64 := base64.StdEncoding.EncodeToString(headerBytes)

	// the same values are expected in the StackState receiver
	// make sure of backward compatibility when changing it
	assert.EqualValues(t, "AwIMAAAAAAAAAAF9f9vd9A==", headerB64)
}

func TestMessageEncodeDecodeConnection(t *testing.T) {
	body := &CollectorConnections{
		HostName: "localhost",
		Connections: []*Connection{
			{
				Pid:                 1234,
				Laddr:               &Addr{Ip: "127.0.0.1", Port: 80},
				Raddr:               &Addr{Ip: "127.0.0.1", Port: 5462},
				ApplicationProtocol: config.PostgresProtocolName,
				Metrics: []*ConnectionMetric{
					{
						Name: "postgres_example",
						Tags: map[string]string{
							"tag1": "value1",
							"tag2": "<unsupported>"},
						Value: &ConnectionMetricValue{
							Value: &ConnectionMetricValue_Number{
								Number: 10,
							},
						},
					},
				},
			},
		},
		GroupId:            0,
		GroupSize:          0,
		ClusterName:        "cluster",
		CollectionInterval: 0,
		Pods:               []*Pod{{}},
	}

	header := MessageHeader{
		Version:   MessageV3,
		Encoding:  MessageEncodingZstdPB,
		Type:      TypeCollectorConnections,
		Timestamp: 2,
	}

	msg := Message{
		Header: header,
		Body:   body,
	}

	// Encode the message
	encodedMsg, err := EncodeMessage(msg)
	assert.NoError(t, err)

	// Decode the message
	decodedMsg, err := DecodeMessage(encodedMsg)
	assert.NoError(t, err)

	if diff := cmp.Diff(msg, decodedMsg); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}
