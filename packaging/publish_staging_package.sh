#!/bin/sh

if [ -z ${STS_AWS_BUCKET+x} ]; then
	echo "Missing STS_AWS_BUCKET in environment"
	exit 1;
fi

if [ -z ${PROCESS_AGENT_VERSION+x} ]; then
	# Pick the latest tag by default for our version.
	PROCESS_AGENT_VERSION=$(./version.sh)
	# But we will be building from the master branch in this case.
fi
echo $PROCESS_AGENT_VERSION
FILENAME="process-agent-amd64-$PROCESS_AGENT_VERSION"
WORKSPACE=${WORKSPACE:-$PWD/../}
agent_path="$WORKSPACE"

aws s3 cp $agent_path/process-agent s3://${STS_AWS_BUCKET:-stackstate-process-agent-test}/binaries/${PACKAGING_BRANCH:-dirty}/$FILENAME --acl public-read
