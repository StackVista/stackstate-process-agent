#!/usr/bin/env bash

set -ex

TARGET_DIR=$(realpath $1)
ls $TARGET_DIR || (echo "$TARGET_DIR does not exists" && false)

MAIN_AGENT_DIR=$(mktemp -d)

echo "Copying stackstate-agent dependency"
MAIN_AGENT_ORIGIN_DIR=$(go list -f '{{ .Dir }}' -m github.com/StackVista/stackstate-agent)
[ ! -z "$MAIN_AGENT_ORIGIN_DIR" ] || (echo "Could not determine path of stackstate-agent module" && false)
cp -r $MAIN_AGENT_ORIGIN_DIR/* $MAIN_AGENT_DIR/

cd $MAIN_AGENT_DIR

echo "Remove subpackages replacements"
chmod ug+w go.mod
cat go.mod | grep 'github.com/StackVista/stackstate-agent/pkg' | grep '=>' | awk '{print $1}' | xargs -I{} go mod edit -dropreplace={}

echo "Build eBPF probes"
chmod ug+w ./pkg/ebpf/bytecode
inv -e system-probe.object-files

cp -r ./pkg/ebpf/bytecode/build/* ${TARGET_DIR}/