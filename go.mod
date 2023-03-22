module github.com/StackVista/stackstate-process-agent

go 1.17

// From datadog-agent-upstream-for-process-agent, replaces done in that go mod file need to be done here too
replace github.com/pahanini/go-grpc-bidirectional-streaming-example v0.0.0-20211027164128-cc6111af44be => github.com/DataDog/go-grpc-bidirectional-streaming-example v0.0.0-20221024060302-b9cf785c02fe

replace github.com/spdx/tools-golang => github.com/spdx/tools-golang v0.3.0

replace github.com/vishvananda/netlink => github.com/DataDog/netlink v1.0.1-0.20220504230202-f7323aba1f6c

replace (
	github.com/benesch/cgosymbolizer => github.com/benesch/cgosymbolizer v0.0.0-20190515212042-bec6fe6e597b
	// next line until pr https://github.com/ianlancetaylor/cgosymbolizer/pull/8 is merged
	github.com/ianlancetaylor/cgosymbolizer => github.com/ianlancetaylor/cgosymbolizer v0.0.0-20170921033129-f5072df9c550
)

// Internal deps fix version
replace (
	bitbucket.org/ww/goautoneg => github.com/munnerz/goautoneg v0.0.0-20120707110453-a547fc61f48d
	github.com/DataDog/sketches-go => github.com/StackVista/sketches-go v1.2.0-pre
	github.com/cihub/seelog => github.com/cihub/seelog v0.0.0-20151216151435-d2c6e5aa9fbf // v2.6
	github.com/docker/distribution => github.com/docker/distribution v2.7.1-0.20190104202606-0ac367fd6bee+incompatible
	github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.4.1
	github.com/iovisor/gobpf => github.com/StackVista/gobpf v0.1.2
	github.com/spf13/viper => github.com/DataDog/viper v1.7.1
	golang.org/x/net => golang.org/x/net v0.0.0-20211015210444-4f30a5c0130f
)

// For local development

// replace github.com/StackVista/stackstate-receiver-go-client => /home/bram/stackvista/agent/src/github.com/StackVista/stackstate-receiver-go-client

// replace github.com/DataDog/datadog-agent => /home/bram/stackvista/agent/src/github.com/StackVista/datadog-agent-upstream-for-process-agent
// replace github.com/DataDog/datadog-agent/pkg/util/log => /home/bram/stackvista/agent/src/github.com/StackVista/datadog-agent-upstream-for-process-agent/pkg/util/log

// replace github.com/DataDog/datadog-agent => github.com/StackVista/datadog-agent-upstream-for-process-agent v0.0.0-20230309153711-2ce9a9612c03
// replace github.com/DataDog/datadog-agent/pkg/util/log => github.com/StackVista/datadog-agent-upstream-for-process-agent/pkg/util/log v0.0.0-20230309153711-2ce9a9612c03

require (
	github.com/DataDog/agent-payload/v5 v5.0.67
	github.com/DataDog/datadog-agent v0.0.0-20230307121454-9e9c7904ced5 // 7.43.1
	github.com/DataDog/datadog-agent/pkg/util/log v0.43.1 // 7.43.1
	github.com/DataDog/gopsutil v1.2.2
	github.com/DataDog/sketches-go v1.4.1
	github.com/DataDog/zstd v1.5.2
	github.com/StackExchange/wmi v1.2.1
	github.com/StackVista/stackstate-receiver-go-client v0.0.0-20230321125458-686dde7f9732
	github.com/StackVista/tcptracer-bpf v7.0.6+incompatible
	github.com/cihub/seelog v0.0.0-20170130134532-f561c5e57575
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/gofrs/uuid v4.0.0+incompatible
	github.com/gogo/protobuf v1.3.2
	github.com/mailru/easyjson v0.7.7
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/shirou/w32 v0.0.0-20160930032740-bb4de0191aa4
	github.com/stretchr/testify v1.8.1
	golang.org/x/sys v0.5.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	cloud.google.com/go v0.105.0 // indirect
	cloud.google.com/go/storage v1.28.0 // indirect
	code.cloudfoundry.org/bbs v0.0.0-20200403215808-d7bc971db0db // indirect
	code.cloudfoundry.org/cfhttp/v2 v2.0.0 // indirect
	code.cloudfoundry.org/garden v0.0.0-20210208153517-580cadd489d2 // indirect
	code.cloudfoundry.org/lager v2.0.0+incompatible // indirect
	code.cloudfoundry.org/tlsconfig v0.0.0-20200131000646-bbe0f8da39b3 // indirect
	github.com/AlekSi/pointer v1.1.0 // indirect
	github.com/DataDog/gohai v0.0.0-20221116153829-5d479901d2e9 // indirect
	github.com/DataDog/mmh3 v0.0.0-20210722141835-012dc69a9e49 // indirect
	github.com/DataDog/nikos v1.10.0 // indirect
	github.com/DataDog/watermarkpodautoscaler v0.5.0-rc.1.0.20220530183114-687bca6395e8 // indirect
	github.com/DisposaBoy/JsonConfigReader v0.0.0-20171218180944-5ea4d0ddac55 // indirect
	github.com/Microsoft/go-winio v0.6.0 // indirect
	github.com/Microsoft/hcsshim v0.9.7 // indirect
	github.com/andybalholm/brotli v1.0.2 // indirect
	github.com/arduino/go-apt-client v0.0.0-20190812130613-5613f843fdc8 // indirect
	github.com/awalterschulze/gographviz v2.0.1+incompatible // indirect
	github.com/aws/aws-sdk-go v1.44.171 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bmizerany/pat v0.0.0-20170815010413-6226ea591a40 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/containerd/cgroups v1.0.4 // indirect
	github.com/containerd/containerd v1.6.19 // indirect
	github.com/containerd/continuity v0.3.0 // indirect
	github.com/containerd/fifo v1.0.0 // indirect
	github.com/containerd/ttrpc v1.1.1-0.20220420014843-944ef4a40df3 // indirect
	github.com/containerd/typeurl v1.0.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/docker/distribution v2.8.1+incompatible // indirect
	github.com/docker/docker v23.0.0-rc.1+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dsnet/compress v0.0.2-0.20210315054119-f66993602bf5 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.20.0 // indirect
	github.com/go-openapi/swag v0.22.3 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/gogo/googleapis v1.4.1 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/googleapis/gax-go/v2 v2.7.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.2 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hectane/go-acl v0.0.0-20190604041725-da78bae5fc95 // indirect
	github.com/imdario/mergo v0.3.13 // indirect
	github.com/jlaffaye/ftp v0.0.0-20200812143550-39e3779af0db // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/josharian/native v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
	github.com/kjk/lzma v0.0.0-20161016003348-3fd93898850d // indirect
	github.com/klauspost/pgzip v1.2.5 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.16 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mdlayher/netlink v1.6.2 // indirect
	github.com/mdlayher/socket v0.2.3 // indirect
	github.com/mholt/archiver/v3 v3.5.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mkrautz/goar v0.0.0-20150919110319-282caa8bd9da // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f // indirect
	github.com/nwaples/rardecode v1.1.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0-rc2 // indirect
	github.com/opencontainers/runc v1.1.3 // indirect
	github.com/opencontainers/runtime-spec v1.0.3-0.20220311020903-6969a0a09ab1 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/philhofer/fwd v1.1.1 // indirect
	github.com/pierrec/lz4/v4 v4.1.15 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_golang v1.14.0
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/common v0.38.0 // indirect
	github.com/prometheus/procfs v0.9.0 // indirect
	github.com/sassoftware/go-rpmutils v0.2.0 // indirect
	github.com/sirupsen/logrus v1.9.0 // indirect
	github.com/smira/go-ftp-protocol v0.0.0-20140829150050-066b75c2b70d // indirect
	github.com/smira/go-xz v0.0.0-20150414201226-0c531f070014 // indirect
	github.com/spf13/afero v1.9.3 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/syndtr/goleveldb v1.0.1-0.20220721030215-126854af5e6d // indirect
	github.com/tedsuo/rata v1.0.0 // indirect
	github.com/tinylib/msgp v1.1.6 // indirect
	github.com/twmb/murmur3 v1.1.6 // indirect
	github.com/ugorji/go/codec v1.2.7 // indirect
	github.com/ulikunitz/xz v0.5.10 // indirect
	github.com/vishvananda/netlink v1.2.0-beta.0.20220404152918-5e915e014938 // indirect
	github.com/vishvananda/netns v0.0.0-20220913150850-18c4f4234207 // indirect
	github.com/vito/go-sse v1.0.0 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	github.com/xor-gate/ar v0.0.0-20170530204233-5c72ae81e2b7 // indirect
	go.opencensus.io v0.24.0 // indirect
	golang.org/x/crypto v0.5.0 // indirect
	golang.org/x/mod v0.7.0 // indirect
	golang.org/x/net v0.7.0 // indirect
	golang.org/x/oauth2 v0.1.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/text v0.7.0 // indirect
	golang.org/x/time v0.1.0 // indirect
	golang.org/x/tools v0.5.0 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	google.golang.org/api v0.103.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20221027153422-115e99e71e1c // indirect
	google.golang.org/grpc v1.51.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gopkg.in/zorkian/go-datadog-api.v2 v2.30.0 // indirect
	k8s.io/api v0.25.5 // indirect
	k8s.io/apimachinery v0.25.5 // indirect
	k8s.io/apiserver v0.25.5 // indirect
	k8s.io/autoscaler/vertical-pod-autoscaler v0.10.0 // indirect
	k8s.io/client-go v0.25.5 // indirect
	k8s.io/component-base v0.25.5 // indirect
	k8s.io/kube-openapi v0.0.0-20221012153701-172d655c2280 // indirect
	k8s.io/metrics v0.25.5 // indirect
	k8s.io/utils v0.0.0-20221108210102-8e77b1f39fe2 // indirect
	sigs.k8s.io/controller-runtime v0.11.2 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)

require (
	cloud.google.com/go/compute v1.12.1 // indirect
	cloud.google.com/go/compute/metadata v0.2.1 // indirect
	cloud.google.com/go/iam v0.6.0 // indirect
	code.cloudfoundry.org/gofileutils v0.0.0-20170111115228-4d0c80011a0f // indirect
	contrib.go.opencensus.io/exporter/prometheus v0.4.2 // indirect
	github.com/CycloneDX/cyclonedx-go v0.7.0 // indirect
	github.com/DataDog/aptly v1.5.0 // indirect
	github.com/DataDog/datadog-agent/pkg/otlp/model v0.43.1 // indirect
	github.com/DataDog/datadog-agent/pkg/quantile v0.43.1 // indirect
	github.com/DataDog/datadog-agent/pkg/trace v0.43.1 // indirect
	github.com/DataDog/datadog-agent/pkg/util/cgroups v0.43.1 // indirect
	github.com/DataDog/datadog-agent/pkg/util/pointer v0.43.1 // indirect
	github.com/DataDog/datadog-agent/pkg/util/scrubber v0.43.1 // indirect
	github.com/DataDog/datadog-go/v5 v5.1.1 // indirect
	github.com/DataDog/ebpf-manager v0.2.2 // indirect
	github.com/DataDog/viper v1.12.0 // indirect
	github.com/DataDog/zstd_0 v0.0.0-20210310093942-586c1286621f // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/acobaugh/osrelease v0.1.0 // indirect
	github.com/avast/retry-go/v4 v4.3.2 // indirect
	github.com/benbjohnson/clock v1.3.0 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cavaliergopher/grab/v3 v3.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.2.0 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/cilium/ebpf v0.10.0 // indirect
	github.com/cloudfoundry-community/go-cfclient v0.0.0-20210621174645-7773f7e22665 // indirect
	github.com/coreos/go-systemd/v22 v22.4.0 // indirect
	github.com/emicklei/go-restful/v3 v3.8.0 // indirect
	github.com/felixge/httpsnoop v1.0.3 // indirect
	github.com/go-delve/delve v1.9.1 // indirect
	github.com/go-kit/log v0.2.1 // indirect
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-sql-driver/mysql v1.6.0 // indirect
	github.com/godbus/dbus/v5 v5.0.6 // indirect
	github.com/google/gnostic v0.6.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.0 // indirect
	github.com/h2non/filetype v1.1.2-0.20210602110014-3305bbb7ac7b // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/iovisor/gobpf v0.2.0 // indirect
	github.com/karrick/godirwalk v1.17.0 // indirect
	github.com/klauspost/compress v1.15.13 // indirect
	github.com/knadh/koanf v1.4.4 // indirect
	github.com/lib/pq v1.10.6 // indirect
	github.com/lufia/plan9stats v0.0.0-20220913051719-115f729f3c8c // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/sys/mountinfo v0.6.2 // indirect
	github.com/moby/sys/signal v0.7.0 // indirect
	github.com/moby/term v0.0.0-20221205130635-1aeaba878587 // indirect
	github.com/mohae/deepcopy v0.0.0-20170603005431-491d3605edfb // indirect
	github.com/mostynb/go-grpc-compression v1.1.17 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/pkg/resourcetotelemetry v0.68.0 // indirect
	github.com/opencontainers/selinux v1.10.2 // indirect
	github.com/power-devops/perfstat v0.0.0-20220216144756-c35f1ee13d7c // indirect
	github.com/prometheus/statsd_exporter v0.22.7 // indirect
	github.com/pytimer/win-netstat v0.0.0-20180710031115-efa1aff6aafc // indirect
	github.com/richardartoul/molecule v0.0.0-20210914193524-25d8911bb85b // indirect
	github.com/rs/cors v1.8.2 // indirect
	github.com/shirou/gopsutil/v3 v3.22.10 // indirect
	github.com/smartystreets/goconvey v1.7.2 // indirect
	github.com/spf13/cobra v1.6.1 // indirect
	github.com/tklauser/go-sysconf v0.3.11 // indirect
	github.com/tklauser/numcpus v0.6.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	github.com/zorkian/go-datadog-api v2.30.0+incompatible // indirect
	go.opentelemetry.io/collector v0.68.0 // indirect
	go.opentelemetry.io/collector/component v0.68.0 // indirect
	go.opentelemetry.io/collector/confmap v0.68.0 // indirect
	go.opentelemetry.io/collector/consumer v0.68.0 // indirect
	go.opentelemetry.io/collector/exporter/loggingexporter v0.68.0 // indirect
	go.opentelemetry.io/collector/exporter/otlpexporter v0.68.0 // indirect
	go.opentelemetry.io/collector/featuregate v0.68.0 // indirect
	go.opentelemetry.io/collector/pdata v1.0.0-rc2 // indirect
	go.opentelemetry.io/collector/processor/batchprocessor v0.68.0 // indirect
	go.opentelemetry.io/collector/receiver/otlpreceiver v0.68.0 // indirect
	go.opentelemetry.io/collector/semconv v0.68.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.37.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.37.0 // indirect
	go.opentelemetry.io/contrib/propagators/b3 v1.12.0 // indirect
	go.opentelemetry.io/otel v1.11.2 // indirect
	go.opentelemetry.io/otel/exporters/prometheus v0.34.0 // indirect
	go.opentelemetry.io/otel/metric v0.34.0 // indirect
	go.opentelemetry.io/otel/sdk v1.11.2 // indirect
	go.opentelemetry.io/otel/sdk/metric v0.34.0 // indirect
	go.opentelemetry.io/otel/trace v1.11.2 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/multierr v1.9.0 // indirect
	go.uber.org/zap v1.24.0 // indirect
	go4.org/netipx v0.0.0-20220812043211-3cc044ffd68d // indirect
	golang.org/x/arch v0.0.0-20190927153633-4e8777c89be4 // indirect
	golang.org/x/exp v0.0.0-20230202163644-54bba9f4231b // indirect
	golang.org/x/term v0.5.0 // indirect
	gotest.tools/v3 v3.2.0 // indirect
	k8s.io/apiextensions-apiserver v0.25.5 // indirect
	k8s.io/cri-api v0.25.5 // indirect
	k8s.io/klog/v2 v2.80.1 // indirect
	k8s.io/kubelet v0.25.5 // indirect
	sigs.k8s.io/custom-metrics-apiserver v1.25.1 // indirect
	sigs.k8s.io/json v0.0.0-20220713155537-f223a00ba0e2 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
)
