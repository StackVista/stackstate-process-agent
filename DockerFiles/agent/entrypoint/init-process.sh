#!/bin/bash

if [[ -z "$STS_API_KEY" ]]; then
    echo "You must set an STS_API_KEY environment variable to run the StackState Process Agent container"
    exit 1
fi

if [[ -z "$STS_PROCESS_AGENT_URL" ]]; then
    echo "You must set an STS_PROCESS_AGENT_URL environment variable to run the StackState Process Agent container"
    exit 1
fi

if [[ $(zcat /host/proc/config.gz | grep -c Chromium) == 1 ]]; then
    echo "Running in Container Optimized OS. Fetching kernel headers..."
    mkdir -p /opt/stackstate-agent/kernel-headers
    source /host/etc/os-release
    echo $BUILD_ID
    wget --no-verbose "https://storage.googleapis.com/cos-tools/${BUILD_ID}/kernel-src.tar.gz"
    tar -xzf kernel-src.tar.gz -C /opt/stackstate-agent/kernel-headers
    cp -r ./kernel-headers/include/uapi/asm-generic ./kernel-headers/include/uapi/asm
fi

/opt/stackstate-agent/bin/agent/process-agent -config /etc/stackstate-agent/stackstate-docker.yaml

