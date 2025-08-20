package telemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/StackVista/stackstate-process-agent/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	instrument "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	defaultResourceServiceName    = "process-agent"
	defaultResourceServiceVersion = "0.1.0"
	defaultInterval               = 30 * time.Second
	meterName                     = "network"

	// SentMetricName is the name of the metric for sent bytes.
	SentMetricName = "agent.network.sent"
	// ReceivedMetricName is the name of the metric for received bytes.
	ReceivedMetricName = "agent.network.received"
	// PostgresClientLatencyName is the name of the metric for Postgres client latency.
	PostgresClientLatencyName = "agent.network.postgres.client.response.time"
	// PostgresServerLatencyName is the name of the metric for Postgres server latency.
	PostgresServerLatencyName = "agent.network.postgres.server.response.time"
)

// MetricsExporter is responsible for exporting metrics.
type MetricsExporter struct {
	provider              *metric.MeterProvider
	Reader                metric.Reader
	BytesSent             instrument.Int64Counter
	BytesRecv             instrument.Int64Counter
	PostgresClientLatency instrument.Float64Histogram
	PostgresServerLatency instrument.Float64Histogram
}

func newResource() (*resource.Resource, error) {
	return resource.Merge(resource.Default(),
		resource.NewWithAttributes(semconv.SchemaURL,
			semconv.ServiceName(defaultResourceServiceName),
			semconv.ServiceVersion(defaultResourceServiceVersion),
		))
}

func createReader(cfg config.ExporterConfig) (metric.Reader, error) {
	var reader metric.Reader
	switch cfg.Type {
	case config.ExporterTypeManual:
		// For tests, we use a ManualReader that doesn't require an exporter.
		reader = metric.NewManualReader()

	case config.ExporterTypeStdout:
		// For debugging, we print to stdout.
		exporter, err := stdoutmetric.New()
		if err != nil {
			return nil, fmt.Errorf("failed to create stdout exporter: %w", err)
		}
		interval := cfg.Interval
		if interval == 0 {
			interval = defaultInterval
		}
		reader = metric.NewPeriodicReader(exporter, metric.WithInterval(interval))

	case config.ExporterTypeOTLP:
		// For production, we send to an OTLP collector via gRPC.
		if cfg.Endpoint == "" {
			return nil, fmt.Errorf("OTLP endpoint must be configured for OTLP exporter")
		}
		// todo!: we should support TLS.
		conn, err := grpc.NewClient(cfg.Endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, fmt.Errorf("failed to create gRPC connection to collector: %w", err)
		}

		exporter, err := otlpmetricgrpc.New(context.Background(), otlpmetricgrpc.WithGRPCConn(conn))
		if err != nil {
			return nil, fmt.Errorf("failed to create OTLP metric exporter: %w", err)
		}
		interval := cfg.Interval
		if interval == 0 {
			interval = defaultInterval
		}
		reader = metric.NewPeriodicReader(exporter, metric.WithInterval(interval))

	default:
		return nil, fmt.Errorf("unknown exporter type: %d", cfg.Type)
	}
	return reader, nil
}

// NewMetricsExporter creates a new MetricsExporter from the provided Config.
func NewMetricsExporter(cfg config.ExporterConfig) (*MetricsExporter, error) {
	res, err := newResource()
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	reader, err := createReader(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create reader: %w", err)
	}

	meterProvider := metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(reader),
	)

	otel.SetMeterProvider(meterProvider)

	meter := meterProvider.Meter(meterName)

	////////////////////////
	// Connection metrics
	////////////////////////
	sent, err := meter.Int64Counter(
		SentMetricName,
		instrument.WithDescription("Total number of bytes sent"),
		instrument.WithUnit("By"),
	)
	if err != nil {
		return nil, err
	}

	received, err := meter.Int64Counter(
		ReceivedMetricName,
		instrument.WithDescription("Total number of bytes received"),
		instrument.WithUnit("By"),
	)
	if err != nil {
		return nil, err
	}

	////////////////////////
	// Protocol metrics
	////////////////////////
	postgresClient, err := meter.Float64Histogram(
		PostgresClientLatencyName,
		instrument.WithDescription("Total response time for Postgres client"),
		instrument.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	postgresServer, err := meter.Float64Histogram(
		PostgresServerLatencyName,
		instrument.WithDescription("Total response time for Postgres server"),
		instrument.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	return &MetricsExporter{
		Reader:                reader,
		provider:              meterProvider,
		BytesSent:             sent,
		BytesRecv:             received,
		PostgresClientLatency: postgresClient,
		PostgresServerLatency: postgresServer,
	}, nil
}
