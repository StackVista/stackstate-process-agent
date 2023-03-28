#!/bin/sh

if [ -z ${STS_AWS_BUCKET+x} ]; then
	echo "Missing STS_AWS_BUCKET in environment"
	exit 1
fi

if [ -z ${PROCESS_AGENT_VERSION+x} ]; then
	echo "$PROCESS_AGENT_VERSION was not set"
	exit 1
fi
echo $PROCESS_AGENT_VERSION
FILENAME="process-agent-amd64-$PROCESS_AGENT_VERSION"
EBPF_FILENAME="process-agent-amd64-$PROCESS_AGENT_VERSION-ebpf.tar.gz"
WORKSPACE=${WORKSPACE:-$PWD/..}
agent_path="$WORKSPACE"

echo "Uploading agent binary"

aws s3 cp $agent_path/process-agent s3://${STS_AWS_BUCKET:-stackstate-process-agent-test}/binaries/${PACKAGING_BRANCH:-dirty}/$FILENAME --acl public-read

tar -cvz -f $agent_path/ebpf-object-files.tar.gz -C $agent_path  ebpf-object-files

aws s3 cp $agent_path/ebpf-object-files.tar.gz s3://${STS_AWS_BUCKET:-stackstate-process-agent-test}/binaries/${PACKAGING_BRANCH:-dirty}/$EBPF_FILENAME --acl public-read