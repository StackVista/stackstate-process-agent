package kube

import (
	"time"

	"github.com/DataDog/datadog-agent/pkg/process/util"
)

// WithPodsByIP allows to set a custom mapping of pod IPs to their info. (Testing purposes)
func WithPodsByIP(podsByIP map[util.Address][]*PodInfo) ObserverOption {
	return func(o *Observer) {
		o.podsByIP = podsByIP
	}
}

// WithNowFunc allows to set a custom function to get the current time. (Testing purposes)
func WithNowFunc(nowFunc func() time.Time) ObserverOption {
	return func(o *Observer) {
		o.nowFunc = nowFunc
	}
}

// WithBootTime allows to set a custom boot time for the observer. (Testing purposes)
func WithBootTime(bootTime time.Time) ObserverOption {
	return func(o *Observer) {
		o.bootTime = bootTime.Unix()
	}
}

// WithLastControlPlaneLatency allows to set a custom control plane latency for the observer. (Testing purposes)
func WithLastControlPlaneLatency(latency time.Duration) ObserverOption {
	return func(o *Observer) {
		o.lastControlPlaneLatency = int64(latency.Seconds())
	}
}
