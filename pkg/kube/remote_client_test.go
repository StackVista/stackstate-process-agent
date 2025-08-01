// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"

	"go.opentelemetry.io/obi/pkg/components/testutil"
	"go.opentelemetry.io/obi/pkg/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kubecache/meta"
)

const (
	serverPort = 51234
	timeout    = 5 * time.Second
)

func TestClientForwardsLastTimestamp(t *testing.T) {
	fcs := startFakeCacheService(t)
	itemTime := int64(1234567890)
	fcs.serverResponses <- &informer.Event{
		Type: informer.EventType_CREATED,
		Resource: &informer.ObjectMeta{
			Name: "svc-1", Namespace: "default",
			StatusTimeEpoch: itemTime - 1,
		},
	}
	fcs.serverResponses <- &informer.Event{
		Type: informer.EventType_CREATED,
		Resource: &informer.ObjectMeta{
			Name: "svc-1", Namespace: "default",
			StatusTimeEpoch: itemTime,
		},
	}
	fcs.serverResponses <- &informer.Event{
		Type: informer.EventType_SYNC_FINISHED,
	}

	// GIVEN a K8s cache client
	svc := cacheSvcClient{
		address:              fmt.Sprintf("127.0.0.1:%d", fcs.port),
		BaseNotifier:         meta.NewBaseNotifier(slog.With("component", "kube.MetadataProvider")),
		syncTimeout:          timeout,
		log:                  slog.With("component", "kube.cacheSvcClient"),
		ctx:                  t.Context(),
		initialReconnectTime: 1 * time.Millisecond,
	}

	// we subscribe a random observer to unblock the client
	svc.Start()
	svc.Subscribe(dummySubscriber{})

	// the server pushed the client message inside this channel on subscription
	firstSubscribe := testutil.ReadChannel(t, fcs.clientMessages, timeout)
	assert.Zero(t, firstSubscribe.FromTimestampEpoch)

	// There is a restart of the server
	fcs.Restart()
	fcs.serverResponses <- &informer.Event{
		Type: informer.EventType_SYNC_FINISHED,
	}

	// THEN the client sends another subscription message, with the timestamp of the last received event
	secondSubscribe := testutil.ReadChannel(t, fcs.clientMessages, timeout)
	assert.Equal(t, itemTime, secondSubscribe.FromTimestampEpoch)
}

// cacheSvcClient requires a subscriber to start processing the events, so we provide a dummy here
type dummySubscriber struct{}

func (f dummySubscriber) ID() string                 { return "fake-subscriber" }
func (f dummySubscriber) On(_ *informer.Event) error { return nil }

// fakeCacheService accepts gRPC requests from the client and records the received messages
// also lets explicit which events forward to the client
type fakeCacheService struct {
	informer.UnimplementedEventStreamServiceServer
	port     int
	err      atomic.Pointer[error]
	server   *grpc.Server
	listener net.Listener

	clientMessages  chan *informer.SubscribeMessage
	serverResponses chan *informer.Event
}

func startFakeCacheService(t *testing.T) *fakeCacheService {
	fcs := &fakeCacheService{
		port:            serverPort,
		clientMessages:  make(chan *informer.SubscribeMessage, 10),
		serverResponses: make(chan *informer.Event, 10),
	}
	t.Cleanup(func() { fcs.server.Stop() })
	fcs.Start()
	return fcs
}

func (fcs *fakeCacheService) Start() {
	fcs.server = grpc.NewServer()
	informer.RegisterEventStreamServiceServer(fcs.server, fcs)

	var err error
	fcs.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", fcs.port))
	if err != nil {
		err := fmt.Errorf("starting TCP connection: %w", err)
		fcs.err.Store(&err)
		return
	}
	go func() {
		if err := fcs.server.Serve(fcs.listener); err != nil {
			err = fmt.Errorf("grpc.Serve returned: %w", err)
			fcs.err.Store(&err)
		}
	}()
}

func (fcs *fakeCacheService) Restart() {
	fcs.server.Stop()
	fcs.listener.Close()
	fcs.Start()
}

func (fcs *fakeCacheService) Err() error {
	if perr := fcs.err.Load(); perr != nil {
		return *perr
	}
	return nil
}

func (fcs *fakeCacheService) Subscribe(message *informer.SubscribeMessage, g grpc.ServerStreamingServer[informer.Event]) error {
	// we push the client message to the channel
	fcs.clientMessages <- message
	// and we forward the server responses to the client
	for msg := range fcs.serverResponses {
		if err := g.Send(msg); err != nil {
			return fmt.Errorf("sending response to client: %w", err)
		}
	}
	return nil
}
