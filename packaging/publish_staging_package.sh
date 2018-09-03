#!/bin/sh

PROCESS_AGENT_VERSION=${CIRCLE_SHA1:-0.0.0}
WORKSPACE=${WORKSPACE:-$PWD/../}
agent_path="$WORKSPACE"

deb-s3 upload --codename ${CIRCLE_BRANCH:-dirty} --bucket ${STS_AWS_BUCKET:-stackstate-process-agent-test} $WORKSPACE/packaging/debian/*.deb
