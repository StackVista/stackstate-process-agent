#!/bin/bash

# Use this to build a new version of the stackstate-process-agent image from within the devcontainer.

./prebuild-datadog-agent.sh --clean
./prebuild-datadog-agent.sh --generate-no-docker
./prebuild-datadog-agent.sh --install-ebpf
rake build

docker build . --tag europe-west4-docker.pkg.dev/stackstate-sandbox-390311/dev/stackstate-process-agent:dev
docker push europe-west4-docker.pkg.dev/stackstate-sandbox-390311/dev/stackstate-process-agent:dev
