// +build !linux

package checks

import (
	"github.com/StackVista/stackstate-process-agent/pkg"
	"time"

	"github.com/StackVista/stackstate-agent/pkg/util/containers"
)

// Container is a singleton ContainerCheck.
var Container = &ContainerCheck{}

// ContainerCheck is a check that returns container metadata and stats.
type ContainerCheck struct {
	sysInfo *pkg.SystemInfo
	lastRun time.Time
}

// Init initializes a ContainerCheck instance.
func (c *ContainerCheck) Init(cfg *config.AgentConfig, info *pkg.SystemInfo) {
	c.sysInfo = info
}

// Name returns the name of the ProcessCheck.
func (c *ContainerCheck) Name() string { return "container" }

// Endpoint returns the endpoint where this check is submitted.
func (c *ContainerCheck) Endpoint() string { return "/api/v1/container" }

// RealTime indicates if this check only runs in real-time mode.
func (c *ContainerCheck) RealTime() bool { return false }

// Run runs the ContainerCheck to collect a list of running containers and the
// stats for each container.
func (c *ContainerCheck) Run(cfg *config.AgentConfig, groupID int32) ([]model.MessageBody, error) {

	return nil, nil
}

// chunkContainers formats and chunks the containers into a slice of chunks using a specific
// number of chunks. len(result) MUST EQUAL chunks.
func chunkContainers(ctrList []*containers.Container, lastRates map[string]pkg.ContainerRateMetrics, lastRun time.Time, chunks, perChunk int) [][]*pkg.Container {
	return make([][]*pkg.Container, chunks)
}

func fmtContainers(ctrList []*containers.Container, lastRates map[string]pkg.ContainerRateMetrics, lastRun time.Time) []*pkg.Container {
	return make([]*pkg.Container, 0)
}
