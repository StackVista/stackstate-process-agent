#!/usr/bin/env bash

# This script launches into a docker container with the current directory mounted to debug builds
set -x

docker run -v "$PWD:/source" -it quay.io/stackstate/datadog_build_deb_x64:3e691150 bash