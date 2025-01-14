#!/bin/bash

set -ex
echo "This script is here to profile a deployed process agent instance."

POD=${1:-node-agent}
PORT=6062

PODNAME=$(kubectl get pods -o=jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | grep $POD)
EXEC_REMOTE="kubectl exec "$PODNAME" -c process-agent --"
FILE=$(mktemp)

echo "Capturing profile from $PODNAME for 10 seconds into $FILE"
$EXEC_REMOTE curl localhost:6062/debug/pprof/profile?seconds=15 > "$FILE"
echo "Profile captured"

go tool pprof -top "$FILE"

rm "$FILE"