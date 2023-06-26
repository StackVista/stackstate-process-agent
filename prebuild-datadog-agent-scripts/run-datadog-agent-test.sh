#!/usr/bin/env bash

# This script is used by prebuild-datadog-agent and CI to generate the prebuild files from a docker container

set -ex

if [ "$1" = "rerun" ]; then
  rm -rf "$WORKDIR" || true
fi

# This command assumes the datadog agent to be mounted at /source-datadog-agent. To avoid outputting to that directory,
# we make a clone before running any commands
mkdir $WORKDIR
cp -a "$SOURCEDIR"/. $WORKDIR
chown -R root:root $WORKDIR
cd $WORKDIR

# Adding a faux tag to make the build pass on the rpo with no tags
git config user.email "you@example.com"
git config user.name "Your Name"
git tag -a 7.0.0 -m 7.0.0

mount -t debugfs none /sys/kernel/debug/ || true

invoke install-tools

invoke system-probe.build

llvm-objdump -S $WORKDIR/pkg/ebpf/bytecode/build/http-debug.o > $OUTPUTDIR/dump.txt

export DD_SYSTEM_PROBE_BPF_DIR=$WORKDIR/pkg/ebpf/bytecode/build/

export STS_TEST_RUN=true

# Selected test suites for testing
echo "Running suites"
invoke test --build-include=linux_bpf --targets=./pkg/network/protocols/http/.,./pkg/network/. --skip-linters
# Only openssl was proven to work, still need to prove gnutls
invoke test --build-include=linux_bpf --targets=./pkg/network/tracer/. --skip-linters  --run="^TestHTTPSObservationViaLibraryIntegration$"

# Does not work yet, needs runtime compilation
# invoke test --build-include=linux_bpf --targets=./pkg/network/tracer/. --skip-linters  --run="^TestHTTPGoTLSAttachProbes$"
# invoke test --build-include=linux_bpf --targets=./pkg/network/tracer/. --skip-linters  --run="\(^TestHTTPSViaLibraryIntegration\)\|\(^TestHTTPSViaLibraryIntegration\)"