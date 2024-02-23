#!/usr/bin/env bash

# This script is used by prebuild-datadog-agent and CI to generate the prebuild files from a docker container

set -ex

if ! type "rsync" > /dev/null; then
  apt install rsync -y --no-install-recommends
fi

if ! test -f /usr/local/bin/docker-compose; then
   curl -SL https://github.com/docker/compose/releases/download/v2.23.3/docker-compose-linux-x86_64 -o /usr/local/bin/docker-compose
   chmod +x /usr/local/bin/docker-compose
fi

# This command assumes the datadog agent to be mounted at /source-datadog-agent. To avoid outputting to that directory,
# we make a clone before running any commands
mkdir -p $WORKDIR
rsync -au "$SOURCEDIR"/. $WORKDIR
chown -R root:root $WORKDIR
cd $WORKDIR

# Adding a faux tag to make the build pass on the rpo with no tags
git config user.email "you@example.com"
git config user.name "Your Name"
git tag -a 7.0.0 -m 7.0.0 || true

mount -t debugfs none /sys/kernel/debug/ || true

invoke install-tools

invoke system-probe.build

llvm-objdump -S $WORKDIR/pkg/ebpf/bytecode/build/usm-debug.o > $OUTPUTDIR/usm_debug.txt
llvm-objdump -S $WORKDIR/pkg/ebpf/bytecode/build/usm.o > $OUTPUTDIR/usm.txt

export DD_SYSTEM_PROBE_BPF_DIR=$WORKDIR/pkg/ebpf/bytecode/build/

export STS_TEST_RUN=true

# Selected test suites for testing
echo "Running suites"

invoke test --build-include=linux_bpf,test --targets=./pkg/network/protocols/http/.,./pkg/network/protocols/mongo/.,./pkg/network/usm/.,./pkg/network/. --skip-linters
# These tests need to run without concurrency
invoke test --build-include=linux_bpf,test --targets=./pkg/process/monitor/. --cpus=1 --skip-linters
# Only openssl was proven to work, still need to prove gnutls
invoke test --build-include=linux_bpf,test --targets=./pkg/network/tracer/. --skip-linters  --test-run-name="^TestHTTPSObservationViaLibraryIntegration$"
invoke test --build-include=linux_bpf,test --cpus=1 --targets=./pkg/network/tracer/. --skip-linters --test-run-name="^TestUSMSuite/prebuilt/TestProtocolClassification/without_nat/mongo$"
invoke test --build-include=linux_bpf,test --cpus=1 --targets=./pkg/network/tracer/. --skip-linters --test-run-name="^TracerSuite/prebuilt/TestTCPInitialSeq"

# Run the tests for MongoDB
# To also run the TLS test, provide a MONGODB_URI for a TLS-enabled instance, e.g.:
# export MONGODB_URI="mongodb+srv://user:pass@my-cluster.mongodb.com/?retryWrites=true&w=majority"
invoke test --build-include=linux_bpf,test --targets=./pkg/network/tracer/. --cpus=1 --skip-linters --test-run-name=".*Mongo.*"

# Run the tests for AMQP
# There is also a TLS test available, but it needs manual intervention as of now.
# See TestAMQPOverTLSStats in tracker_usm_linux_test.go
invoke test --build-include=linux_bpf,test --targets=./pkg/network/tracer/. --cpus=1 --skip-linters --test-run-name="^TestAMQPStats$"

# Does not work yet, needs runtime compilation
# invoke test --build-include=linux_bpf,test --targets=./pkg/network/tracer/. --skip-linters  --run="^TestHTTPGoTLSAttachProbes$"
# invoke test --build-include=linux_bpf,test --targets=./pkg/network/tracer/. --skip-linters  --run="\(^TestHTTPSViaLibraryIntegration\)\|\(^TestHTTPSViaLibraryIntegration\)"

# Run an individual test
# invoke test --build-include=linux_bpf,test --targets=./pkg/network/usm/. --cpus=1 --skip-linters --test-run-name="TestHTTP/prebuilt/TestHTTPMonitorInstructionCounts"

