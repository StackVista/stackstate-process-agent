#!/bin/bash

# Use this to build a new version of the stackstate-process-agent image from within the devcontainer.

./prebuild-datadog-agent.sh --clean
./prebuild-datadog-agent.sh --generate-no-docker
./prebuild-datadog-agent.sh --install-ebpf
rake build

docker build . --tag europe-west4-docker.pkg.dev/stackstate-sandbox-390311/dev/stackstate-process-agent:dev
docker push europe-west4-docker.pkg.dev/stackstate-sandbox-390311/dev/stackstate-process-agent:dev

cat << EOF
Run it like so:

docker run \\
    --rm \\
    -it \\
    --privileged \\
    -e STS_API_KEY=none \\
    -e STS_PROCESS_AGENT_URL=none \\
    -e STS_CLUSTER_AGENT_ENABLED=true \\
    -e STS_LOG_TO_CONSOLE=true \\
    -v /sys/kernel/debug:/sys/kernel/debug \\
    -e HOST_ETC=/host/etc \\
    -e HOST_SYS=/host/sys \\
    -e HOST_PROC=/host/proc \\
    -v /sys:/host/sys \\
    -v /proc:/host/proc \\
    -v /etc:/host/etc \\
    -e STS_NETWORK_TRACING_ENABLED=true \\
    -e STS_PROTOCOL_INSPECTION_ENABLED=true \\
    europe-west4-docker.pkg.dev/stackstate-sandbox-390311/dev/stackstate-process-agent:dev

EOF
