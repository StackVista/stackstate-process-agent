#!/usr/bin/env bash

# This script is used by prebuild-datadog-agent and CI to generate the prebuild files from a docker container

set -ex

export DD_SYSTEM_PROBE_BPF_DIR=$WORKDIR/pkg/ebpf/bytecode/build/
export DD_ENABLE_RUNTIME_COMPILER=true
export DD_ALLOW_PRECOMPILED_FALLBACK=false
export DD_ENABLE_CO_RE=false
export STS_TEST_RUN=true

if ! type "rsync" > /dev/null; then
  apt install rsync -y --no-install-recommends
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

# Selected test suites for testing
echo "Running suites"

# These require runtime compilation. Running them first to fail fast.
invoke test --build-include=linux_bpf,test --targets=./pkg/network/tracer/. --skip-linters  --test-run-name="^TestHTTPGoTLSAttachProbes$"
invoke test --build-include=linux_bpf,test --targets=./pkg/network/tracer/. --skip-linters  --test-run-name="\(^TestHTTPSViaLibraryIntegration\)\|\(^TestHTTPSViaLibraryIntegration\)"

# The default set of tests, no special requirements here
invoke test --build-include=linux_bpf,test --targets=./pkg/network/protocols/http/.,./pkg/network/usm/.,./pkg/network/. --skip-linters

# These tests need to run without concurrency
invoke test --build-include=linux_bpf,test --targets=./pkg/process/monitor/. --cpus=1 --skip-linters

# Only openssl was proven to work, still need to prove gnutls
invoke test --build-include=linux_bpf,test --targets=./pkg/network/tracer/. --skip-linters  --test-run-name="^TestHTTPSObservationViaLibraryIntegration$"

# Run an individual test
# invoke test --build-include=linux_bpf,test --targets=./pkg/process/monitor/. --cpus=1 --skip-linters --test-run-name="^TestProcessMonitorInNamespace$"
