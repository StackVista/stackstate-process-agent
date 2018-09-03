#!/bin/sh

PROCESS_AGENT_VERSION=${CIRCLE_SHA1:-0.0.0}
WORKSPACE=${WORKSPACE:-$PWD/../}
agent_path="$WORKSPACE"

mkdir -p "$agent_path/packaging/debian/package/opt/dd-process-agent/bin/"
mkdir -p "$agent_path/packaging/debian/package/opt/dd-process-agent/run/"
mkdir -p "$agent_path/packaging/rpm/package/opt/dd-process-agent/bin/"
mkdir -p "$agent_path/packaging/rpm/package/opt/dd-process-agent/run/"

# copy the binary
cp "$agent_path/process-agent" "$agent_path/packaging/debian/package/opt/dd-process-agent/bin/sts-process-agent"
cp "$agent_path/process-agent" "$agent_path/packaging/rpm/package/opt/dd-process-agent/bin/sts-process-agent"

# make debian package using fpm
echo "Building debian package..."
cd $agent_path/packaging/debian
fpm -s dir -t deb -v "$PROCESS_AGENT_VERSION" -n sts-process-agent --license="Simplified BSD License" --maintainer="StackVista" --vendor "StackVista" \
--url="https://www.stackstate.com/" --category Network --description "An agent for collecting and submitting process information to StackState (https://www.stackstate.com/)" \
 -a "amd64" --before-remove dd-process-agent.prerm --after-install dd-process-agent.postinst --after-upgrade dd-process-agent.postup \
 --before-upgrade dd-process-agent.preup --deb-init dd-process-agent.init -C $agent_path/packaging/debian/package .

# make rpm package using fpm
echo "Building rpm package..."
cd $agent_path/packaging/rpm
fpm -s dir -t rpm -v "$PROCESS_AGENT_VERSION" -n sts-process-agent --license="Simplified BSD License" --maintainer="StackVista" --vendor "StackVista" \
--url="https://www.stackstate.com/" --category Network --description "An agent for collecting and submitting process information to StackState (https://www.stackstate.com/)" \
 -a "amd64" --rpm-init dd-process-agent.init --before-remove dd-process-agent.prerm --after-install dd-process-agent.postinst --after-upgrade dd-process-agent.postup \
 --before-upgrade dd-process-agent.preup -C $agent_path/packaging/rpm/package .

