#!/bin/sh

PROTOC_VERSION=3.6.1

curl -OL https://github.com/google/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip
echo "6003de742ea3fcf703cfec1cd4a3380fd143081a2eb0e559065563496af27807 protoc-${PROTOC_VERSION}-linux-x86_64.zip" | sha256sum --check
unzip protoc-${PROTOC_VERSION}-linux-x86_64.zip -d /usr/local