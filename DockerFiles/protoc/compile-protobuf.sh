#!/usr/bin/env bash

set -ex

export GOPATH=/go

export PATH="$(go env GOPATH)/bin:${PATH}"

cd /go/src/github.com/gogo/protobuf
make install

protoc \
		github.com/StackVista/stackstate-process-agent/proto/agent.proto \
		github.com/StackVista/stackstate-process-agent/proto/agent_payload.proto \
		-I /go/src \
		--gogofaster_out /model


mv "/model/github.com/StackVista/stackstate-process-agent/model/"* /model/
