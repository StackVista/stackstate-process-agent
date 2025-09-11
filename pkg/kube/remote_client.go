package kube

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/obi/pkg/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kubecache/meta"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	maxReconnectTime = 2 * time.Minute
)

type cacheSvcClient struct {
	meta.BaseNotifier
	address                string
	log                    *slog.Logger
	lastEventTSEpoch       int64
	ctx                    context.Context
	syncTimeout            time.Duration
	waitForSubscription    chan struct{}
	waitForSynchronization chan struct{}
	waitForSyncClosed      bool
	initialReconnectTime   time.Duration
	reconnectTime          time.Duration
}

func (sc *cacheSvcClient) Start() {
	// in this case the client waits for an observer to subscribe
	sc.waitForSubscription = make(chan struct{})
	// in this case the observer waits for the client to synchronize
	sc.waitForSynchronization = make(chan struct{})
	sc.reconnectTime = sc.initialReconnectTime

	go func() {
		select {
		case <-sc.ctx.Done():
			sc.log.Debug("context done, stopping client")
			return
		// We wait for an observer to subscribe to the client, otherwise we will not start the connection with the remote cache
		case <-sc.waitForSubscription:
			sc.log.Debug("subscriptor attached, start connection to K8s cache service")
		}

		for {
			select {
			case <-sc.ctx.Done():
				sc.log.Debug("context done, stopping client")
				return
			default:
				sc.log.Info("Connecting to K8s cache service", "address", sc.address)
				err := sc.connect(sc.ctx)
				sc.log.Warn("K8s cache service connection lost. Reconnecting...", "error", err)
				time.Sleep(sc.reconnectTime)
				if sc.reconnectTime < maxReconnectTime {
					sc.reconnectTime *= 2
				} else {
					sc.reconnectTime = maxReconnectTime
				}
			}
		}
	}()
}

func (sc *cacheSvcClient) connect(ctx context.Context) error {
	// Set up a connection to the server.
	conn, err := grpc.NewClient(sc.address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("did not connect: %w", err)
	}
	defer conn.Close()

	// if the connection is established, restore the reconnect time
	sc.reconnectTime = sc.initialReconnectTime

	client := informer.NewEventStreamServiceClient(conn)

	// Subscribe to the event stream. receive all the events since the last event timestamp (initially 0)
	stream, err := client.Subscribe(ctx, &informer.SubscribeMessage{
		FromTimestampEpoch: sc.lastEventTSEpoch,
	})
	if err != nil {
		return fmt.Errorf("could not subscribe: %w", err)
	}

	// Receive and print messages.
	for {
		event, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("error receiving message: %w", err)
		}

		// we received the initial snapshot of the metadata, so the observer can start enriching events
		if event.GetType() == informer.EventType_SYNC_FINISHED && !sc.waitForSyncClosed {
			close(sc.waitForSynchronization)
			sc.waitForSyncClosed = true
		}

		// While we are waiting for `EventType_SYNC_FINISHED`, we call the On method of the observer to process the events
		sc.Notify(event)

		// we keep track of the last event timestamp to avoid receiving again all the messages in case of a reconnection
		if event.GetType() != informer.EventType_SYNC_FINISHED && event.Resource != nil {
			sc.lastEventTSEpoch = event.Resource.StatusTimeEpoch
		}
	}
}

func (sc *cacheSvcClient) Subscribe(observer meta.Observer) {
	sc.BaseNotifier.Subscribe(observer)
	close(sc.waitForSubscription)

	// if we are called by the observer it means we have at least one subscriber so we start the connection with the remote cache.
	// We pause the subscriber until the connection is established.

	sc.log.Info("waiting for K8s metadata synchronization", "timeout", sc.syncTimeout)
	select {
	case <-sc.waitForSynchronization:
		sc.log.Debug("K8s metadata cache service synchronized")
	case <-sc.ctx.Done():
		sc.log.Debug("context done. Nothing to do")
	case <-time.After(sc.syncTimeout):
		sc.log.Warn("timed out while waiting for K8s metadata synchronization. Some metadata might be temporarily missing.")
	}
}
