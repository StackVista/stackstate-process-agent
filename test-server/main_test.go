package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerTerminationConditions(t *testing.T) {
	url := fmt.Sprintf("http://localhost:%s/stsAgent/api/v1/connections", port)

	tests := []struct {
		name            string
		terminationFunc func(t *testing.T)
		expectedMatch   bool
	}{
		{
			name: "Valid postgres message triggers shutdown",
			terminationFunc: func(t *testing.T) {
				// Craft a fake `TypeCollectorConnections` message
				m := &model.CollectorConnections{
					Connections: []*model.Connection{
						{
							Pid:                 1234,
							ApplicationProtocol: config.PostgresProtocolName,
							Metrics: []*model.ConnectionMetric{{Tags: map[string]string{
								"command":  "SELECT",
								"database": "demo",
							}}, {}},
						},
					},
				}

				body, err := model.EncodeMessage(model.Message{
					Header: model.MessageHeader{
						Version:  model.MessageV3,
						Encoding: model.MessageEncodingZstdPB,
						Type:     model.TypeCollectorConnections,
					},
					Body: m,
				})
				if err != nil {
					t.Fatalf("Error encoding message: %v", err)
				}

				resp, err := http.Post(url, "application/x-protobuf", bytes.NewReader(body))
				if err != nil {
					t.Fatalf("Request failed: %v", err)
				}
				defer resp.Body.Close()

				// Read response
				res, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("Unexpected response status: %d, body: %s", resp.StatusCode, string(res))
				}

				t.Logf("Server response OK")
			},
			expectedMatch: true,
		},
		{
			name: "Reach max requests limit",
			terminationFunc: func(t *testing.T) {
				m := &model.CollectorConnections{}
				body, err := model.EncodeMessage(model.Message{
					Header: model.MessageHeader{
						Version:  model.MessageV3,
						Encoding: model.MessageEncodingZstdPB,
						Type:     model.TypeCollectorConnections,
					},
					Body: m,
				})
				if err != nil {
					t.Fatalf("Error encoding message: %v", err)
				}

				for i := 0; i < maxRequests; i++ {
					resp, err := http.Post(url, "application/x-protobuf", bytes.NewReader(body))
					if err != nil {
						t.Fatalf("Request failed: %v", err)
					}
					defer resp.Body.Close()

					// Read response
					res, _ := io.ReadAll(resp.Body)
					if resp.StatusCode != http.StatusOK {
						t.Fatalf("Unexpected response status: %d, body: %s", resp.StatusCode, string(res))
					}

					t.Logf("Server response '%d' OK", i+1)
				}
			},
			expectedMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				match := run()
				assert.Equal(t, tt.expectedMatch, match)
				wg.Done()
			}()

			go func() {
				// Backup goroutine to terminate the test if the server does not answer in time
				time.Sleep(10 * time.Second)
				t.Log("Server did not respond in time, terminating test")
				wg.Done()
			}()

			// Wait for the server to be ready
			require.Eventually(t, func() bool {
				resp, err := http.Get(url)
				if err == nil {
					resp.Body.Close()
					return true
				}
				return false
			}, 2*time.Second, 10*time.Millisecond, "Server not ready")

			tt.terminationFunc(t)

			// Wait for the server to terminate
			wg.Wait()
		})
	}
}
