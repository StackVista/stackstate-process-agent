module github.com/StackVista/stackstate-process-agent

go 1.23.0

toolchain go1.23.5

// From datadog-agent-upstream-for-process-agent, replaces done in that go mod file need to be done here too
replace github.com/pahanini/go-grpc-bidirectional-streaming-example v0.0.0-20211027164128-cc6111af44be => github.com/DataDog/go-grpc-bidirectional-streaming-example v0.0.0-20221024060302-b9cf785c02fe

replace github.com/aquasecurity/trivy => github.com/DataDog/trivy v0.0.0-20241223234648-d2ac813bf11b

replace github.com/vishvananda/netlink => github.com/StackVista/netlink v0.0.0-20231207101142-91d41874606b

replace github.com/google/gopacket v1.1.19 => github.com/DataDog/gopacket v0.0.0-20240626205202-4ac4cee31f14

replace (
	github.com/benesch/cgosymbolizer => github.com/benesch/cgosymbolizer v0.0.0-20190515212042-bec6fe6e597b
	// next line until pr https://github.com/ianlancetaylor/cgosymbolizer/pull/8 is merged
	github.com/ianlancetaylor/cgosymbolizer => github.com/ianlancetaylor/cgosymbolizer v0.0.0-20170921033129-f5072df9c550
)

replace k8s.io/cri-api => k8s.io/cri-api v0.25.5

// Internal deps fix copied from datadog-agent-upstream (should be updated on update)
replace (
	github.com/coreos/go-systemd => github.com/coreos/go-systemd v0.0.0-20180202092358-40e2722dffea
	github.com/spf13/cast => github.com/DataDog/cast v1.8.0
	github.com/ugorji/go => github.com/ugorji/go v1.1.7
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
)

require (
	github.com/DataDog/agent-payload/v5 v5.0.138
	github.com/DataDog/datadog-agent v0.0.0-20230307121454-9e9c7904ced5 // 7.43.1
	github.com/DataDog/datadog-agent/pkg/util/log v0.62.2 // 7.49.1
	github.com/DataDog/gopsutil v1.2.2
	github.com/DataDog/sketches-go v1.4.6
	github.com/DataDog/zstd v1.5.6
	github.com/StackExchange/wmi v1.2.1 // indirect
	github.com/StackVista/stackstate-receiver-go-client v0.0.0-20250224145616-f9b4a1fa7d2b
	github.com/cihub/seelog v0.0.0-20170130134532-f561c5e57575
	github.com/gofrs/uuid v4.3.1+incompatible
	github.com/gogo/protobuf v1.3.2
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/shirou/w32 v0.0.0-20160930032740-bb4de0191aa4 // indirect
	github.com/stretchr/testify v1.10.0
	golang.org/x/sys v0.28.0 // indirect
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/AlekSi/pointer v1.2.0 // indirect
	github.com/DataDog/mmh3 v0.0.0-20210722141835-012dc69a9e49 // indirect
	github.com/DataDog/nikos v1.12.9 // indirect
	github.com/DataDog/watermarkpodautoscaler v0.5.3-0.20241023200123-ab786c1724cf // indirect
	github.com/DisposaBoy/JsonConfigReader v0.0.0-20201129172854-99cf318d67e7 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/Microsoft/hcsshim v0.12.9 // indirect
	github.com/awalterschulze/gographviz v2.0.3+incompatible // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/containerd/containerd v1.7.23 // indirect
	github.com/containerd/continuity v0.4.3 // indirect
	github.com/containerd/fifo v1.1.0 // indirect
	github.com/containerd/ttrpc v1.2.5 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/docker/distribution v2.8.3+incompatible // indirect
	github.com/docker/docker v27.4.0+incompatible // indirect
	github.com/docker/go-connections v0.5.0 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fatih/color v1.18.0 // indirect
	github.com/fsnotify/fsnotify v1.8.0 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-openapi/jsonpointer v0.21.0 // indirect
	github.com/go-openapi/jsonreference v0.21.0 // indirect
	github.com/go-openapi/swag v0.23.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/golang/snappy v0.0.5-0.20220116011046-fa5810519dcb // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.7 // indirect
	github.com/hashicorp/hcl v1.0.1-vault-5 // indirect
	github.com/hectane/go-acl v0.0.0-20230122075934-ca0b05cb1adb // indirect
	github.com/imdario/mergo v0.3.16 // indirect
	github.com/jlaffaye/ftp v0.1.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
	github.com/kjk/lzma v0.0.0-20161016003348-3fd93898850d // indirect
	github.com/klauspost/pgzip v1.2.6 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.5.0 // indirect
	github.com/mitchellh/mapstructure v1.5.1-0.20231216201459-8508981c8b6c // indirect
	github.com/mkrautz/goar v0.0.0-20150919110319-282caa8bd9da // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/opencontainers/runtime-spec v1.2.0 // indirect
	github.com/pborman/uuid v1.2.1
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/philhofer/fwd v1.1.3-0.20240916144458-20a13a1f6b7c // indirect
	github.com/pierrec/lz4/v4 v4.1.21 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_golang v1.20.5
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.60.1 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/sassoftware/go-rpmutils v0.4.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/smira/go-ftp-protocol v0.0.0-20140829150050-066b75c2b70d // indirect
	github.com/smira/go-xz v0.1.0 // indirect
	github.com/spf13/afero v1.11.0 // indirect
	github.com/spf13/cast v1.7.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/syndtr/goleveldb v1.0.1-0.20220721030215-126854af5e6d // indirect
	github.com/tinylib/msgp v1.2.4 // indirect
	github.com/twmb/murmur3 v1.1.8 // indirect
	github.com/ugorji/go/codec v1.2.11 // indirect
	github.com/ulikunitz/xz v0.5.12 // indirect
	github.com/vishvananda/netlink v1.3.0 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	github.com/xor-gate/ar v0.0.0-20170530204233-5c72ae81e2b7 // indirect
	go.opencensus.io v0.24.0 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/mod v0.22.0 // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/oauth2 v0.23.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	golang.org/x/time v0.8.0 // indirect
	golang.org/x/tools v0.28.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
	google.golang.org/genproto v0.0.0-20240903143218-8af14fe29dc1 // indirect
	google.golang.org/grpc v1.67.1 // indirect
	google.golang.org/protobuf v1.35.2 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/api v0.31.4 // indirect
	k8s.io/apimachinery v0.31.4 // indirect
	k8s.io/autoscaler/vertical-pod-autoscaler v0.13.0 // indirect
	k8s.io/client-go v0.31.3 // indirect
	k8s.io/kube-openapi v0.0.0-20240430033511-f0e62f92d13f // indirect
	k8s.io/utils v0.0.0-20240821151609-f90d01438635
	sigs.k8s.io/controller-runtime v0.19.0 // indirect
	sigs.k8s.io/yaml v1.4.0 // indirect
)

require (
	github.com/DataDog/datadog-agent/comp/core/telemetry v0.62.2
	github.com/DataDog/datadog-agent/pkg/config/model v0.62.2
	github.com/DataDog/datadog-agent/pkg/config/setup v0.62.2
	github.com/DataDog/datadog-agent/pkg/util/filesystem v0.62.2
	k8s.io/kubelet v0.31.2
)

require (
	code.cloudfoundry.org/bbs v0.0.0-20200403215808-d7bc971db0db // indirect
	code.cloudfoundry.org/cfhttp/v2 v2.0.0 // indirect
	code.cloudfoundry.org/garden v0.0.0-20210208153517-580cadd489d2 // indirect
	code.cloudfoundry.org/lager v2.0.0+incompatible // indirect
	code.cloudfoundry.org/tlsconfig v0.0.0-20200131000646-bbe0f8da39b3 // indirect
	dario.cat/mergo v1.0.1 // indirect
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20230811130428-ced1acdcaa24 // indirect
	github.com/AdamKorcz/go-118-fuzz-build v0.0.0-20230306123547-8075edf89bb0 // indirect
	github.com/BurntSushi/toml v1.4.1-0.20240526193622-a339e1f7089c // indirect
	github.com/CycloneDX/cyclonedx-go v0.9.1 // indirect
	github.com/DataDog/aptly v1.5.3 // indirect
	github.com/DataDog/datadog-agent/comp/api/api/def v0.62.2 // indirect
	github.com/DataDog/datadog-agent/comp/core/config v0.62.2 // indirect
	github.com/DataDog/datadog-agent/comp/core/flare/builder v0.62.2 // indirect
	github.com/DataDog/datadog-agent/comp/core/flare/types v0.62.2 // indirect
	github.com/DataDog/datadog-agent/comp/core/hostname/hostnameinterface v0.62.2 // indirect
	github.com/DataDog/datadog-agent/comp/core/log/def v0.62.2 // indirect
	github.com/DataDog/datadog-agent/comp/core/log/impl v0.62.2 // indirect
	github.com/DataDog/datadog-agent/comp/core/log/mock v0.62.2 // indirect
	github.com/DataDog/datadog-agent/comp/core/secrets v0.62.2 // indirect
	github.com/DataDog/datadog-agent/comp/core/tagger/origindetection v0.62.2 // indirect
	github.com/DataDog/datadog-agent/comp/core/tagger/tags v0.62.2 // indirect
	github.com/DataDog/datadog-agent/comp/core/tagger/types v0.62.2 // indirect
	github.com/DataDog/datadog-agent/comp/core/tagger/utils v0.62.2 // indirect
	github.com/DataDog/datadog-agent/comp/def v0.62.2 // indirect
	github.com/DataDog/datadog-agent/comp/logs/agent/config v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/api v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/collector/check/defaults v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/config/env v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/config/mock v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/config/nodetreemodel v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/config/structure v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/config/teeconfig v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/config/utils v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/errors v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/logs/client v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/logs/message v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/logs/metrics v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/logs/sources v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/logs/status/utils v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/proto v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/security/secl v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/status/health v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/tagger/types v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/tagset v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/telemetry v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/backoff v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/cache v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/cgroups v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/common v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/containers/image v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/executable v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/flavor v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/fxutil v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/grpc v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/hostname/validate v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/http v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/json v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/log/setup v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/optional v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/pointer v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/scrubber v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/sort v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/statstracker v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/system v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/system/socket v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/testutil v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/util/winutil v0.62.2 // indirect
	github.com/DataDog/datadog-agent/pkg/version v0.62.2 // indirect
	github.com/DataDog/datadog-go/v5 v5.6.0 // indirect
	github.com/DataDog/ebpf-manager v0.7.6 // indirect
	github.com/DataDog/go-sqllexer v0.0.17 // indirect
	github.com/DataDog/viper v1.14.0 // indirect
	github.com/DataDog/zstd_0 v0.0.0-20210310093942-586c1286621f // indirect
	github.com/Intevation/gval v1.3.0 // indirect
	github.com/Intevation/jsonpath v0.2.1 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/Masterminds/semver/v3 v3.3.1 // indirect
	github.com/Masterminds/sprig/v3 v3.3.0 // indirect
	github.com/ProtonMail/go-crypto v1.1.3 // indirect
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/acobaugh/osrelease v0.1.0 // indirect
	github.com/agext/levenshtein v1.2.3 // indirect
	github.com/alecthomas/participle v0.7.1 // indirect
	github.com/alecthomas/units v0.0.0-20240626203959-61d1e3462e30 // indirect
	github.com/anchore/go-struct-converter v0.0.0-20221118182256-c68fdcfa2092 // indirect
	github.com/aquasecurity/go-gem-version v0.0.0-20201115065557-8eed6fe000ce // indirect
	github.com/aquasecurity/go-npm-version v0.0.0-20201110091526-0b796d180798 // indirect
	github.com/aquasecurity/go-pep440-version v0.0.0-20210121094942-22b2f8951d46 // indirect
	github.com/aquasecurity/go-version v0.0.0-20240603093900-cf8a8d29271d // indirect
	github.com/aquasecurity/table v1.8.0 // indirect
	github.com/aquasecurity/tml v0.6.1 // indirect
	github.com/aquasecurity/trivy v0.49.2-0.20240227072422-e1ea02c7b80d // indirect
	github.com/aquasecurity/trivy-db v0.0.0-20240910133327-7e0f4d2ed4c1 // indirect
	github.com/aquasecurity/trivy-java-db v0.0.0-20240109071736-184bd7481d48 // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/avast/retry-go/v4 v4.6.0 // indirect
	github.com/aws/aws-sdk-go-v2 v1.32.6 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.28.6 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.47 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.21 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.25 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.25 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ebs v1.22.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.190.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.24.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.28.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.2 // indirect
	github.com/aws/smithy-go v1.22.1 // indirect
	github.com/benbjohnson/clock v1.3.5 // indirect
	github.com/bitnami/go-version v0.0.0-20231130084017-bb00604d650c // indirect
	github.com/blang/semver v3.5.1+incompatible // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/bmatcuk/doublestar/v4 v4.7.1 // indirect
	github.com/bmizerany/pat v0.0.0-20170815010413-6226ea591a40 // indirect
	github.com/briandowns/spinner v1.23.0 // indirect
	github.com/cavaliergopher/grab/v3 v3.0.1 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cheggaaa/pb/v3 v3.1.5 // indirect
	github.com/cilium/ebpf v0.16.0 // indirect
	github.com/cloudflare/cbpfc v0.0.0-20240920015331-ff978e94500b // indirect
	github.com/cloudflare/circl v1.3.8 // indirect
	github.com/cloudfoundry-community/go-cfclient/v2 v2.0.1-0.20230503155151-3d15366c5820 // indirect
	github.com/containerd/cgroups/v3 v3.0.4 // indirect
	github.com/containerd/containerd/api v1.8.0 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v0.2.1 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.15.1 // indirect
	github.com/containerd/typeurl/v2 v2.2.3 // indirect
	github.com/containernetworking/cni v1.2.3 // indirect
	github.com/containernetworking/plugins v1.4.1 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/cri-o/ocicni v0.4.3 // indirect
	github.com/csaf-poc/csaf_distribution/v3 v3.0.0 // indirect
	github.com/cyberphone/json-canonicalization v0.0.0-20231011164504-785e29786b46 // indirect
	github.com/cyphar/filepath-securejoin v0.3.4 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/digitorus/pkcs7 v0.0.0-20230818184609-3a137a874352 // indirect
	github.com/digitorus/timestamp v0.0.0-20231217203849-220c5c2851b7 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/cli v27.4.0+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.8.2 // indirect
	github.com/ebitengine/purego v0.8.1 // indirect
	github.com/emicklei/go-restful/v3 v3.12.1 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/glaslos/ssdeep v0.4.0 // indirect
	github.com/go-chi/chi v4.1.2+incompatible // indirect
	github.com/go-delve/delve v1.23.1 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.6.0 // indirect
	github.com/go-git/go-git/v5 v5.13.0 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/analysis v0.23.0 // indirect
	github.com/go-openapi/errors v0.22.0 // indirect
	github.com/go-openapi/loads v0.22.0 // indirect
	github.com/go-openapi/runtime v0.28.0 // indirect
	github.com/go-openapi/spec v0.21.0 // indirect
	github.com/go-openapi/strfmt v0.23.0 // indirect
	github.com/go-openapi/validate v0.24.0 // indirect
	github.com/go-redis/redis/v8 v8.11.5 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/golang-jwt/jwt/v4 v4.5.1 // indirect
	github.com/google/certificate-transparency-go v1.1.8 // indirect
	github.com/google/gnostic-models v0.6.9-0.20230804172637-c7be7c783f49 // indirect
	github.com/google/go-containerregistry v0.20.2 // indirect
	github.com/google/go-github/v62 v62.0.0 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/wire v0.6.0 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/gorilla/websocket v1.5.1 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.16.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.23.0 // indirect
	github.com/h2non/filetype v1.1.3 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/huandu/xstrings v1.5.0 // indirect
	github.com/in-toto/in-toto-golang v0.9.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/pgx/v5 v5.6.0 // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jedisct1/go-minisign v0.0.0-20230811132847-661be99b8267 // indirect
	github.com/jellydator/ttlcache/v3 v3.3.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/justincormack/go-memfd v0.0.0-20170219213707-6e4af0518993 // indirect
	github.com/karrick/godirwalk v1.17.0 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f // indirect
	github.com/knqyf263/go-deb-version v0.0.0-20230223133812-3ed183d23422 // indirect
	github.com/knqyf263/go-rpm-version v0.0.0-20220614171824-631e686d1075 // indirect
	github.com/knqyf263/go-rpmdb v0.1.1 // indirect
	github.com/knqyf263/nested v0.0.1 // indirect
	github.com/letsencrypt/boulder v0.0.0-20231026200631-000cd05d5491 // indirect
	github.com/liamg/jfather v0.0.7 // indirect
	github.com/lorenzosaino/go-sysctl v0.3.1 // indirect
	github.com/lufia/plan9stats v0.0.0-20240226150601-1dcf7310316a // indirect
	github.com/lunixbochs/struc v0.0.0-20200707160740-784aaebc1d40 // indirect
	github.com/masahiro331/go-disk v0.0.0-20240625071113-56c933208fee // indirect
	github.com/masahiro331/go-ebs-file v0.0.0-20240917043618-e6d2bea5c32e // indirect
	github.com/masahiro331/go-ext4-filesystem v0.0.0-20240620024024-ca14e6327bbd // indirect
	github.com/masahiro331/go-mvn-version v0.0.0-20210429150710-d3157d602a08 // indirect
	github.com/masahiro331/go-vmdk-parser v0.0.0-20221225061455-612096e4bbbd // indirect
	github.com/masahiro331/go-xfs-filesystem v0.0.0-20231205045356-1b22259a6c44 // indirect
	github.com/mattn/go-runewidth v0.0.15 // indirect
	github.com/mattn/go-shellwords v1.0.12 // indirect
	github.com/microsoft/go-rustaudit v0.0.0-20220808201409-204dfee52032 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/hashstructure/v2 v2.0.2 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/buildkit v0.16.0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/spdystream v0.4.0 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/sequential v0.5.0 // indirect
	github.com/moby/sys/signal v0.7.1 // indirect
	github.com/moby/sys/user v0.3.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826 // indirect
	github.com/montanaflynn/stats v0.7.0 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/nozzle/throttler v0.0.0-20180817012639-2ea982251481 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/opencontainers/selinux v1.11.0 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/openvex/discovery v0.1.1-0.20240802171711-7c54efc57553 // indirect
	github.com/openvex/go-vex v0.2.5 // indirect
	github.com/owenrumney/go-sarif/v2 v2.3.3 // indirect
	github.com/package-url/packageurl-go v0.1.3 // indirect
	github.com/pjbgf/sha1cd v0.3.0 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/puzpuzpuz/xsync/v3 v3.4.0 // indirect
	github.com/redis/go-redis/v9 v9.5.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/rs/zerolog v1.33.0 // indirect
	github.com/samber/lo v1.47.0 // indirect
	github.com/santhosh-tekuri/jsonschema/v5 v5.3.1 // indirect
	github.com/sassoftware/relic v7.2.1+incompatible // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.8.0 // indirect
	github.com/sergi/go-diff v1.3.2-0.20230802210424-5b0b94c5c0d3 // indirect
	github.com/shibumi/go-pathspec v1.3.0 // indirect
	github.com/shirou/gopsutil/v4 v4.24.11 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/sigstore/cosign/v2 v2.2.4 // indirect
	github.com/sigstore/rekor v1.3.6 // indirect
	github.com/sigstore/sigstore v1.8.3 // indirect
	github.com/sigstore/timestamp-authority v1.2.2 // indirect
	github.com/skeema/knownhosts v1.3.0 // indirect
	github.com/skydive-project/go-debouncer v1.0.0 // indirect
	github.com/spdx/tools-golang v0.5.5 // indirect
	github.com/spf13/cobra v1.8.1 // indirect
	github.com/spf13/viper v1.19.0 // indirect
	github.com/streadway/amqp v1.1.0 // indirect
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635 // indirect
	github.com/tedsuo/rata v1.0.0 // indirect
	github.com/tetratelabs/wazero v1.8.0 // indirect
	github.com/theupdateframework/go-tuf v0.7.0 // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399 // indirect
	github.com/tklauser/go-sysconf v0.3.14 // indirect
	github.com/tklauser/numcpus v0.8.0 // indirect
	github.com/tmthrgd/go-hex v0.0.0-20190904060850-447a3041c3bc // indirect
	github.com/tonistiigi/go-csvvalue v0.0.0-20240710180619-ddb21b71c0b4 // indirect
	github.com/transparency-dev/merkle v0.0.2 // indirect
	github.com/twitchtv/twirp v8.1.3+incompatible // indirect
	github.com/twmb/franz-go v1.17.0 // indirect
	github.com/twmb/franz-go/pkg/kadm v1.12.0 // indirect
	github.com/twmb/franz-go/pkg/kmsg v1.8.0 // indirect
	github.com/uptrace/bun v1.2.5 // indirect
	github.com/uptrace/bun/dialect/pgdialect v1.2.5 // indirect
	github.com/uptrace/bun/driver/pgdriver v1.2.5 // indirect
	github.com/vbatts/tar-split v0.11.5 // indirect
	github.com/vito/go-sse v1.0.0 // indirect
	github.com/vmihailenco/msgpack/v5 v5.4.1 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.2 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/xlab/treeprint v1.2.0 // indirect
	github.com/youmark/pkcs8 v0.0.0-20181117223130-1be2e3e5546d // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	github.com/zorkian/go-datadog-api v2.30.0+incompatible // indirect
	go.etcd.io/bbolt v1.3.11 // indirect
	go.etcd.io/etcd/pkg/v3 v3.6.0-alpha.0 // indirect
	go.mongodb.org/mongo-driver v1.15.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.56.0 // indirect
	go.opentelemetry.io/otel v1.32.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.31.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.31.0 // indirect
	go.opentelemetry.io/otel/metric v1.32.0 // indirect
	go.opentelemetry.io/otel/sdk v1.32.0 // indirect
	go.opentelemetry.io/otel/trace v1.32.0 // indirect
	go.opentelemetry.io/proto/otlp v1.3.1 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/dig v1.18.0 // indirect
	go.uber.org/fx v1.23.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	go4.org/intern v0.0.0-20230525184215-6c62f75575cb // indirect
	go4.org/netipx v0.0.0-20220812043211-3cc044ffd68d // indirect
	go4.org/unsafe/assume-no-moving-gc v0.0.0-20231121144256-b99613f794b6 // indirect
	golang.org/x/arch v0.12.0 // indirect
	golang.org/x/exp v0.0.0-20241210194714-1829a127f884 // indirect
	golang.org/x/exp/typeparams v0.0.0-20240314144324-c7f7c6466f7f // indirect
	golang.org/x/lint v0.0.0-20241112194109-818c5a804067 // indirect
	golang.org/x/term v0.27.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20241104194629-dd2ea8efbc28 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241104194629-dd2ea8efbc28 // indirect
	gopkg.in/cheggaaa/pb.v1 v1.0.28 // indirect
	gopkg.in/evanphx/json-patch.v4 v4.12.0 // indirect
	gopkg.in/go-jose/go-jose.v2 v2.6.3 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/zorkian/go-datadog-api.v2 v2.30.0 // indirect
	gotest.tools/v3 v3.5.1 // indirect
	honnef.co/go/tools v0.5.1 // indirect
	k8s.io/apiextensions-apiserver v0.31.2 // indirect
	k8s.io/apiserver v0.31.2 // indirect
	k8s.io/component-base v0.31.2 // indirect
	k8s.io/cri-api v0.31.2 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
	k8s.io/kube-aggregator v0.31.2 // indirect
	k8s.io/metrics v0.31.2 // indirect
	mellium.im/sasl v0.3.2 // indirect
	modernc.org/gc/v3 v3.0.0-20240107210532-573471604cb6 // indirect
	modernc.org/libc v1.55.3 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.8.0 // indirect
	modernc.org/sqlite v1.34.1 // indirect
	modernc.org/strutil v1.2.0 // indirect
	modernc.org/token v1.1.0 // indirect
	rsc.io/binaryregexp v0.2.0 // indirect
	sigs.k8s.io/custom-metrics-apiserver v1.30.1-0.20241105195130-84dc8cfe2555 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
)

replace github.com/moby/buildkit v0.11.0 => github.com/moby/buildkit v0.12.5

replace github.com/DataDog/datadog-agent => github.com/StackVista/datadog-agent-upstream-for-process-agent v0.0.0-20250508090931-440aa0115bd6
