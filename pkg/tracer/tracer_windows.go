package tracer

import (
	"github.com/StackVista/stackstate-process-agent/pkg/tracer/collector"
	"github.com/StackVista/stackstate-process-agent/pkg/tracer/common"
	"github.com/StackVista/stackstate-process-agent/pkg/tracer/config"
	logger "github.com/cihub/seelog"
)

type WindowsTracer struct {
	collector.Collector
	TracerConfig *config.Config
}

func MakeTracer(config *config.Config) (Tracer, error) {
	tracer := &WindowsTracer{
		Collector:    collector.MakeNetstatCollector(),
		TracerConfig: config,
	}

	return tracer, nil
}

func CheckTracerSupport() (bool, error) {
	return true, nil
}

func (t *WindowsTracer) Start() error {
	return nil
}

func (t *WindowsTracer) Stop() {}

func (t *WindowsTracer) GetTCPConnections() ([]*common.ConnectionStats, error) {
	v4conns, err := t.GetTCPv4Connections()

	if err != nil {
		return nil, err
	}

	v6conns, err := t.GetTCPv6Connections()
	if err != nil {
		return nil, err
	}

	return append(v4conns, v6conns...), nil
}

func (t *WindowsTracer) GetUDPConnections() ([]*common.ConnectionStats, error) {
	v4conns, err := t.GetUDPv4Connections()
	if err != nil {
		return nil, err
	}

	v6conns, err := t.GetUDPv6Connections()
	if err != nil {
		return nil, err
	}

	return append(v4conns, v6conns...), nil
}

func (t *WindowsTracer) GetConnections() (*common.Connections, error) {
	var conns []*common.ConnectionStats

	if t.TracerConfig.CollectTCPConns {
		tcpConns, err := t.GetTCPConnections()
		if err != nil {
			return nil, err
		}
		conns = append(conns, tcpConns...)
	}

	if t.TracerConfig.CollectUDPConns {
		udpConns, err := t.GetUDPConnections()
		if err != nil {
			return nil, err
		}
		conns = append(conns, udpConns...)
	}

	connectionStats := make([]common.ConnectionStats, 0)

	for _, conn := range conns {
		if len(connectionStats) >= t.TracerConfig.MaxConnections {
			logger.Warnf("Exceeded maximum connections %d", t.TracerConfig.MaxConnections)
			break
		}
		connectionStats = append(connectionStats, *conn)
	}

	return &common.Connections{Conns: connectionStats}, nil
}