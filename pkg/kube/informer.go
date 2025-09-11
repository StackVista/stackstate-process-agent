package kube

import (
	"context"
	"log/slog"
	"time"

	log "github.com/cihub/seelog"

	"go.opentelemetry.io/obi/pkg/kubecache/meta"
)

const defaultReconnectTime = 5 * time.Second

// InformerConfig holds the configuration for the Kubernetes informers.
type InformerConfig struct {
	DisabledInformers []string
	KubeConfigPath    string
	SyncTimeout       time.Duration
	ResyncPeriod      time.Duration
	// MetaCacheAddress is the host:port address
	MetaCacheAddr string
	LogLevel      string
}

func initRemoteInformerCacheClient(ctx context.Context, addr string, syncTimeout time.Duration) (*cacheSvcClient, error) {
	client := &cacheSvcClient{
		address:              addr,
		BaseNotifier:         meta.NewBaseNotifier(slog.With("component", "kube.MetadataProvider")),
		syncTimeout:          syncTimeout,
		log:                  slog.With("component", "kube.cacheSvcClient"),
		ctx:                  ctx,
		initialReconnectTime: defaultReconnectTime,
	}
	client.Start()
	return client, nil
}

func initLocalInformers(ctx context.Context, cfg InformerConfig) (*meta.Informers, error) {
	var opts []meta.InformerOption
	opts = append(opts,
		// we don't want informers on services and nodes
		meta.WithoutNodes(),
		meta.WithoutServices(),
		meta.WithResyncPeriod(cfg.ResyncPeriod),
		meta.WithKubeConfigPath(cfg.KubeConfigPath),
		// we don't want that the informer starts decorating spans and flows
		// before getting all the existing K8s metadata
		meta.WaitForCacheSync(),
		meta.LocalInstance(),
		meta.WithCacheSyncTimeout(cfg.SyncTimeout),
	)
	return meta.InitInformers(ctx, opts...)
}

func setSlogLoggerLevel(level string) {
	switch level {
	case "trace":
	case "debug":
		slog.SetLogLoggerLevel(slog.LevelDebug)
	case "info":
		slog.SetLogLoggerLevel(slog.LevelInfo)
	case "warn":
		slog.SetLogLoggerLevel(slog.LevelWarn)
	case "error":
	case "critical":
		slog.SetLogLoggerLevel(slog.LevelError) // critical is not a level in slog,
	default:
		// there is no an equivalent in slog for "off" so we put it to error
		slog.SetLogLoggerLevel(slog.LevelError)

	}
}

// GetInformer returns a Notifier that can be used to get Kubernetes metadata.
func GetInformer(cfg InformerConfig) (meta.Notifier, error) {
	// this is the logger OBI uses and we cannot change it, so we just use the same verbosity of our logger.
	setSlogLoggerLevel(cfg.LogLevel)
	if cfg.MetaCacheAddr != "" {
		log.Infof("Using remote K8s cache service at '%s'", cfg.MetaCacheAddr)
		return initRemoteInformerCacheClient(context.Background(), cfg.MetaCacheAddr, cfg.SyncTimeout)
	}
	log.Infof("Using local K8s informers with kubeconfig path: '%s'", cfg.KubeConfigPath)
	return initLocalInformers(context.Background(), cfg)
}
