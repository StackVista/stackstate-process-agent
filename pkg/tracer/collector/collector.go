package collector

import "github.com/StackVista/stackstate-process-agent/pkg/tracer/common"

type Collector interface {
	GetTCPv4Connections() ([]*common.ConnectionStats, error)
	GetTCPv6Connections() ([]*common.ConnectionStats, error)
	GetUDPv4Connections() ([]*common.ConnectionStats, error)
	GetUDPv6Connections() ([]*common.ConnectionStats, error)
}

// TODO: Convert collector to use Response
type Response struct {
	Connections []*common.ConnectionStats
	Error       error
}

func (res *Response) AndThen(f func() *Response) *Response {
	if res.Error != nil {
		return res
	}

	return f()
}
