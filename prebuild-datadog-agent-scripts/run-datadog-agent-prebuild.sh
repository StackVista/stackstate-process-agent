#!/usr/bin/env bash

# This script is used by prebuild-datadog-agent and CI to generate the prebuild files from a docker container

set -ex

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

# This command will create system-probe. Running the go:generate as well as invoking the precompilation of the ebpf files
invoke system-probe.build

# Output the generated gofiles (including relative paths) to the output directory
mkdir -p "$OUTPUTDIR/gofiles"
git ls-files --others --ignored --exclude-from=.gitignore | grep "\.go$" | xargs -I{} cp --parents {} "$OUTPUTDIR/gofiles"
chown -R "$OUTPUT_USER_ID:$OUTPUT_GROUP_ID" "$OUTPUTDIR/gofiles"

# Output the ebpf files to the output directory
mkdir -p "$OUTPUTDIR/ebpf/"
cp -r ./pkg/ebpf/bytecode/build/* "$OUTPUTDIR/ebpf/"
chown -R "$OUTPUT_USER_ID:$OUTPUT_GROUP_ID" "$OUTPUTDIR/ebpf"

