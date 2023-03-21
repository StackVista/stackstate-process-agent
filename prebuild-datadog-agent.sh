#!/usr/bin/env bash

# Okay, here it goes: The process agent depends on the datadog agent, which:
# - for some modules (EBPF) uses go:generate which needs to be run to even build the dependency.
# - for some other modules generate EBPF code, which we need but is not part of the regular go build
# This file makes sure those prebuild steps (go:generate and ebpf files) get built and installed.

#!/bin/bash

set -e

DIR="${BASH_SOURCE%/*}"
if [[ ! -d "$DIR" ]]; then DIR="$PWD"; fi
if [[ "$DIR" = "." ]]; then DIR="$PWD"; fi

function printUsage() {
  cat << USAGE

Usage: ./prebuild-datadog-agent.sh --generate|--clean|--shell|--install-go|--help

This script run the prebuild steps for the datadog agent dependency. Those steps are not automatically invoked by the go build.
  -g/--generate   -- Generate the prebuild files
  -c/--clean      -- Clean the generated files
  -i/--install-go -- Install the prebuild go files
  -s/--shell      -- Launch into a shell in which the prebuild files are built
  -h/--help       -- Print this help page

USAGE
}

ACTION=""

while [[ $# -gt 0 ]]; do
  case $1 in
    -g|--generate)
      ACTION="generate"
      shift
    ;;
    -i|--install-go)
      ACTION="install-go"
      shift
    ;;
    -s|--shell)
      ACTION="shell"
      shift
    ;;
    -c|--clean)
      ACTION="clean"
      shift
    ;;
    -h|--help)
      ACTION="help"
      shift
    ;;
    *)
      ACTION="$1"
      shift
      break
    ;;
  esac
done

ALL_ARTIFACTS_DIR="$DIR/prebuild_artifacts"

GO_MOD_DEPENDENCY_DIR=$(go list -f '{{ .Dir }}' -m github.com/DataDog/datadog-agent)

# Check if the dependency was replaced
if [ "$(go list -f '{{ .Replace }}' -m github.com/DataDog/datadog-agent)" = "<nil>" ]; then
    DEPENDENCY_VERSION=$(go list -f '{{ .Version }}' -m github.com/DataDog/datadog-agent)
    REPO_PATH="https://github.com/DataDog/datadog-agent"
    SOURCE_DIR="$ALL_ARTIFACTS_DIR/$DEPENDENCY_VERSION/checkout"
else
  GO_MOD_DEPENDENCY_DIR=$(go list -f '{{ .Replace.Dir }}' -m github.com/DataDog/datadog-agent)

  if [ -d "$GO_MOD_REPLACE_DEPENDENCY_DIR/.git" ]; then
    echo "Running the data prebuild for a local dependency $DEPENDENCY_VERSION. Be aware that generate will not automatically pickup changes. Be sure to run -clean whenever the generated code would change."
    # The dependency is a local git repo. No need to pull or pick a version
    DEPENDENCY_VERSION="local"
    SOURCE_DIR=$GO_MOD_REPLACE_DEPENDENCY_DIR
  else
    echo "Running for replacement git remote"
    DEPENDENCY_VERSION=$(go list -f '{{ .Replace.Version }}' -m github.com/DataDog/datadog-agent)
    REPO_PATH="https://$(go list -f '{{ .Replace.Path }}' -m github.com/DataDog/datadog-agent)"
    SOURCE_DIR="$ALL_ARTIFACTS_DIR/$DEPENDENCY_VERSION/checkout"
  fi
fi

DEPENDENCY_ARTIFACTS_DIR="$ALL_ARTIFACTS_DIR/$DEPENDENCY_VERSION"
DOCKER_IMAGE=artifactory.tooling.stackstate.io/docker-virtual/stackstate/datadog_build_system-probe_x64:5151a592

function runPrebuild() {
  if [ ! -d "$SOURCE_DIR" ]; then
    echo "datadog-agent was not cloned, cloning"
    mkdir -p $DEPENDENCY_ARTIFACTS_DIR
    GIT_VERSION=$(echo "$DEPENDENCY_VERSION" | cut -d'-' -f 3)
    (cd $DEPENDENCY_ARTIFACTS_DIR &&
      git clone "$REPO_PATH" checkout &&
      cd checkout &&
      git checkout "$GIT_VERSION")
  fi

  set -x
  docker run \
    -e "OUTPUT_USER_ID=$(id -u "${USER}")" \
    -e "OUTPUT_GROUP_ID=$(id -g "${USER}")" \
    -v "$SOURCE_DIR":/source-datadog-agent \
    -e SOURCEDIR="/source-datadog-agent" \
    -v "$DEPENDENCY_ARTIFACTS_DIR":/output \
    -e OUTPUTDIR="/output" \
    -v "$DIR/prebuild-datadog-agent-scripts":/scripts \
    "$@"
  set +x
}

if [[ "$ACTION" = "generate" ]]; then
  echo "Generating code"
  if [ -d "$DEPENDENCY_ARTIFACTS_DIR" ]; then
    echo "Prebuild artifacts were already generated. Skipping. To regenerate first run with --clean"
  fi

  mkdir -p "$DEPENDENCY_ARTIFACTS_DIR"
  runPrebuild "$DOCKER_IMAGE" /scripts/run-datadog-agent-prebuild.sh
elif [[ "$ACTION" = "install-go" ]]; then
  echo "Installing go files"
  if [ ! -d "$DEPENDENCY_ARTIFACTS_DIR/gofiles" ]; then
    echo "No generated files found at $DEPENDENCY_ARTIFACTS_DIR/golang, please run --generate first"
    exit 1
  fi

  chmod -R ug+w "$GO_MOD_DEPENDENCY_DIR"
  cp -a "$DEPENDENCY_ARTIFACTS_DIR/gofiles"/* "$GO_MOD_DEPENDENCY_DIR"
elif [[ "$ACTION" = "clean" ]]; then
  echo "Cleaning prebuild files from $PREBUILD_ARTIFACTS_DIR"
  rm -rf "$ALL_ARTIFACTS_DIR"
elif [[ "$ACTION" = "shell" ]]; then
  echo "Launching generate shell"
  runPrebuild -it "$DOCKER_IMAGE" /bin/bash
elif [[ -z "$ACTION" ]]; then
  echo "No argument was passed"
  printUsage
  exit 1
else
  echo "Illegal argument $ACTION"
  printUsage
  exit 1
fi
