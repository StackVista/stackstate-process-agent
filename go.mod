module github.com/StackVista/stackstate-process-agent

go 1.17

replace (
	github.com/benesch/cgosymbolizer => github.com/benesch/cgosymbolizer v0.0.0-20190515212042-bec6fe6e597b
	// next line until pr https://github.com/ianlancetaylor/cgosymbolizer/pull/8 is merged
	github.com/ianlancetaylor/cgosymbolizer => github.com/ianlancetaylor/cgosymbolizer v0.0.0-20170921033129-f5072df9c550
)

// Internal deps fix version
replace (
	bitbucket.org/ww/goautoneg => github.com/munnerz/goautoneg v0.0.0-20120707110453-a547fc61f48d
	github.com/DataDog/sketches-go v1.2.1 => github.com/StackVista/sketches-go v1.1.1
	github.com/cihub/seelog => github.com/cihub/seelog v0.0.0-20151216151435-d2c6e5aa9fbf // v2.6
	github.com/docker/distribution => github.com/docker/distribution v2.7.1-0.20190104202606-0ac367fd6bee+incompatible
	github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.4.1
	github.com/iovisor/gobpf => github.com/StackVista/gobpf v0.1.2
	github.com/prometheus/client_golang => github.com/prometheus/client_golang v0.9.2
	github.com/spf13/viper => github.com/DataDog/viper v1.7.1
	golang.org/x/net => golang.org/x/net v0.0.0-20211015210444-4f30a5c0130f
	google.golang.org/grpc => github.com/grpc/grpc-go v1.28.0
)

replace k8s.io/api => k8s.io/api v0.21.5 // indirect

require (
	github.com/DataDog/gopsutil v0.0.0-20211112180027-9aa392ae181a
	github.com/DataDog/sketches-go v1.2.1
	github.com/DataDog/zstd v1.4.8
	github.com/StackExchange/wmi v1.2.1
	github.com/StackVista/stackstate-agent v0.0.0-20221121195532-a5c5f0dfec3b
	github.com/StackVista/stackstate-agent/pkg/util/log v0.19.0-rc.4
	github.com/StackVista/stackstate-go v0.0.0-20220302151729-a72c49c07350
	github.com/StackVista/tcptracer-bpf v7.0.6+incompatible
	github.com/cihub/seelog v0.0.0-20170130134532-f561c5e57575
	github.com/go-ini/ini v1.63.2
	github.com/gogo/protobuf v1.3.2
	github.com/mailru/easyjson v0.7.7
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/shirou/w32 v0.0.0-20160930032740-bb4de0191aa4
	github.com/stretchr/testify v1.7.0
	golang.org/x/sys v0.1.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	code.cloudfoundry.org/bbs v0.0.0-20200403215808-d7bc971db0db // indirect
	code.cloudfoundry.org/cfhttp/v2 v2.0.0 // indirect
	code.cloudfoundry.org/garden v0.0.0-20210208153517-580cadd489d2 // indirect
	code.cloudfoundry.org/lager v2.0.0+incompatible // indirect
	code.cloudfoundry.org/tlsconfig v0.0.0-20200131000646-bbe0f8da39b3 // indirect
	github.com/DataDog/datadog-go v4.8.2+incompatible // indirect
	github.com/DataDog/gohai v0.0.0-20210303102637-6b668acb50dd // indirect
	github.com/DataDog/mmh3 v0.0.0-20210722141835-012dc69a9e49 // indirect
	github.com/DataDog/watermarkpodautoscaler v0.3.1-logs-attributes.2.0.20211014120627-6d6a5c559fc9 // indirect
	github.com/Microsoft/go-winio v0.5.1 // indirect
	github.com/Microsoft/hcsshim v0.9.0 // indirect
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/armon/go-metrics v0.3.0 // indirect
	github.com/aws/aws-sdk-go v1.40.38 // indirect
	github.com/benesch/cgosymbolizer v0.0.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bhmj/jsonslice v0.0.0-20200323023432-92c3edaad8e2 // indirect
	github.com/blang/semver v3.5.1+incompatible // indirect
	github.com/bmizerany/pat v0.0.0-20170815010413-6226ea591a40 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/containerd/cgroups v1.0.2 // indirect
	github.com/containerd/containerd v1.5.7 // indirect
	github.com/containerd/continuity v0.1.0 // indirect
	github.com/containerd/fifo v1.0.0 // indirect
	github.com/containerd/ttrpc v1.0.2 // indirect
	github.com/containerd/typeurl v1.0.2 // indirect
	github.com/coreos/go-semver v0.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v17.12.0-ce-rc1.0.20200916142827-bd33bbf0497b+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/emicklei/go-restful v2.14.3+incompatible // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/go-ole/go-ole v1.2.5 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.6 // indirect
	github.com/go-openapi/spec v0.20.4 // indirect
	github.com/go-openapi/swag v0.19.15 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/gogo/googleapis v1.4.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.6 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/googleapis/gnostic v0.5.1 // indirect
	github.com/hashicorp/consul/api v1.11.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-hclog v0.12.0 // indirect
	github.com/hashicorp/go-immutable-radix v1.1.0 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.1 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hashicorp/serf v0.9.5 // indirect
	github.com/hectane/go-acl v0.0.0-20190604041725-da78bae5fc95 // indirect
	github.com/ianlancetaylor/cgosymbolizer v0.0.0-20201204192058-7acc97e53614 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
	github.com/magiconair/properties v1.8.5 // indirect
	github.com/mattn/go-colorable v0.1.9 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.4.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/opencontainers/runc v1.0.2 // indirect
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417 // indirect
	github.com/pelletier/go-toml v1.9.3 // indirect
	github.com/philhofer/fwd v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_golang v1.11.0 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.32.1 // indirect
	github.com/prometheus/procfs v0.6.0 // indirect
	github.com/samuel/go-zookeeper v0.0.0-20190923202752-2cc03de413da // indirect
	github.com/shirou/gopsutil v3.21.9+incompatible // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/spf13/afero v1.6.0 // indirect
	github.com/spf13/cast v1.4.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/tedsuo/rata v1.0.0 // indirect
	github.com/tinylib/msgp v1.1.6 // indirect
	github.com/twmb/murmur3 v1.1.6 // indirect
	github.com/vishvananda/netns v0.0.0-20210104183010-2eb08e3e575f // indirect
	github.com/vito/go-sse v1.0.0 // indirect
	go.opencensus.io v0.23.0 // indirect
	golang.org/x/crypto v0.0.0-20210616213533-5ff15b29337e // indirect
	golang.org/x/mobile v0.0.0-20201217150744-e6ae53a27f4f // indirect
	golang.org/x/net v0.1.0 // indirect
	golang.org/x/oauth2 v0.0.0-20210514164344-f6687ab2804c // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/time v0.0.0-20210220033141-f8bda1e9f3ba // indirect
	google.golang.org/appengine v1.6.6 // indirect
	google.golang.org/genproto v0.0.0-20210604141403-392c879c8b08 // indirect
	google.golang.org/grpc v1.42.0 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
	gopkg.in/zorkian/go-datadog-api.v2 v2.30.0 // indirect
	k8s.io/api v0.21.5 // indirect
	k8s.io/apimachinery v0.21.5 // indirect
	k8s.io/apiserver v0.21.5 // indirect
	k8s.io/autoscaler/vertical-pod-autoscaler v0.9.2 // indirect
	k8s.io/client-go v0.21.5 // indirect
	k8s.io/component-base v0.21.5 // indirect
	k8s.io/klog v1.0.1-0.20200310124935-4ad0115ba9e4 // indirect
	k8s.io/kube-openapi v0.0.0-20210305001622-591a79e4bda7 // indirect
	k8s.io/metrics v0.21.5 // indirect
	k8s.io/utils v0.0.0-20201110183641-67b214c5f920 // indirect
	sigs.k8s.io/controller-runtime v0.7.2 // indirect
	sigs.k8s.io/yaml v1.2.0 // indirect
)

require (
	code.cloudfoundry.org/gofileutils v0.0.0-20170111115228-4d0c80011a0f // indirect
	contrib.go.opencensus.io/exporter/prometheus v0.4.0 // indirect
	github.com/DataDog/agent-payload/v5 v5.0.4 // indirect
	github.com/DataDog/gostackparse v0.5.0 // indirect
	github.com/DataDog/viper v1.9.0 // indirect
	github.com/DataDog/zstd_0 v0.0.0-20210310093942-586c1286621f // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/StackVista/stackstate-agent/pkg/otlp/model v0.19.0-rc.4 // indirect
	github.com/StackVista/stackstate-agent/pkg/quantile v0.19.0-rc.4 // indirect
	github.com/StackVista/stackstate-agent/pkg/util/scrubber v0.19.0-rc.4 // indirect
	github.com/StackVista/stackstate-agent/pkg/util/winutil v0.19.0-rc.4 // indirect
	github.com/benbjohnson/clock v1.1.0 // indirect
	github.com/bits-and-blooms/bitset v1.2.0 // indirect
	github.com/cenkalti/backoff/v4 v4.1.1 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/cloudfoundry-community/go-cfclient v0.0.0-20210621174645-7773f7e22665 // indirect
	github.com/coreos/go-systemd/v22 v22.3.2 // indirect
	github.com/cyphar/filepath-securejoin v0.2.2 // indirect
	github.com/dgraph-io/ristretto v0.1.0 // indirect
	github.com/felixge/httpsnoop v1.0.2 // indirect
	github.com/go-kit/log v0.1.0 // indirect
	github.com/go-logfmt/logfmt v0.5.0 // indirect
	github.com/go-logr/logr v0.4.0 // indirect
	github.com/godbus/dbus/v5 v5.0.4 // indirect
	github.com/golang/glog v1.0.0 // indirect
	github.com/google/pprof v0.0.0-20210423192551-a2663126120b // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/gosnmp/gosnmp v1.32.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.16.0 // indirect
	github.com/h2non/filetype v1.1.2-0.20210602110014-3305bbb7ac7b // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/iovisor/gobpf v0.2.0 // indirect
	github.com/klauspost/compress v1.13.5 // indirect
	github.com/knadh/koanf v1.3.0 // indirect
	github.com/kubernetes-sigs/custom-metrics-apiserver v0.0.0-20210311094424-0ca2b1909cdc // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/sys/mountinfo v0.4.1 // indirect
	github.com/mohae/deepcopy v0.0.0-20170603005431-491d3605edfb // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/pkg/resourcetotelemetry v0.38.0 // indirect
	github.com/opencontainers/selinux v1.8.2 // indirect
	github.com/prometheus/statsd_exporter v0.21.0 // indirect
	github.com/pytimer/win-netstat v0.0.0-20180710031115-efa1aff6aafc // indirect
	github.com/richardartoul/molecule v0.0.0-20210914193524-25d8911bb85b // indirect
	github.com/rs/cors v1.8.0 // indirect
	github.com/shirou/gopsutil/v3 v3.21.9 // indirect
	github.com/smartystreets/goconvey v1.7.2 // indirect
	github.com/spf13/cobra v1.2.1 // indirect
	github.com/tent/canonical-json-go v0.0.0-20130607151641-96e4ba3a7613 // indirect
	github.com/theupdateframework/go-tuf v0.0.0-20210921152604-1c7bbcecec00 // indirect
	github.com/tklauser/go-sysconf v0.3.9 // indirect
	github.com/tklauser/numcpus v0.3.0 // indirect
	go.etcd.io/bbolt v1.3.6 // indirect
	go.etcd.io/etcd/api/v3 v3.5.0 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.5.0 // indirect
	go.etcd.io/etcd/client/v2 v2.305.0 // indirect
	go.opentelemetry.io/collector v0.38.0 // indirect
	go.opentelemetry.io/collector/model v0.38.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.25.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.25.0 // indirect
	go.opentelemetry.io/contrib/zpages v0.25.0 // indirect
	go.opentelemetry.io/otel v1.0.1 // indirect
	go.opentelemetry.io/otel/exporters/prometheus v0.24.0 // indirect
	go.opentelemetry.io/otel/internal/metric v0.24.1-0.20211006140346-3d4ae8d0b75f // indirect
	go.opentelemetry.io/otel/metric v0.24.0 // indirect
	go.opentelemetry.io/otel/sdk v1.0.1 // indirect
	go.opentelemetry.io/otel/sdk/export/metric v0.24.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v0.24.0 // indirect
	go.opentelemetry.io/otel/trace v1.0.1 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.7.0 // indirect
	go.uber.org/zap v1.19.1 // indirect
	golang.org/x/term v0.0.0-20210220032956-6a3ed077a48d // indirect
	gopkg.in/DataDog/dd-trace-go.v1 v1.33.0 // indirect
	k8s.io/klog/v2 v2.9.0 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.1.2 // indirect
)
