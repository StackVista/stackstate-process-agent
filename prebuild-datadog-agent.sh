#!/usr/bin/env sh

# Okay, here it goes: The process agent depends on the datadog agent, which:
# - for some modules (EBPF) uses go:generate which needs to be run to even build the dependency.
# - for some other modules generate EBPF code, which we need but is not part of the regular go build
# This file makes sure those prebuild steps (go:generate and ebpf files) get built and installed.

set -e

DIR="${BASH_SOURCE%/*}"
if [ ! -d "$DIR" ]; then DIR="$PWD"; fi
if [ "$DIR" = "." ]; then DIR="$PWD"; fi

printUsage() {
  cat << USAGE

Usage: ./prebuild-datadog-agent.sh --generate|--clean|--shell|--install-go|--help

This script run the prebuild steps for the datadog agent dependency. Those steps are not automatically invoked by the go build.
  -g/--generate   -- Generate the prebuild files by running inside a docker container
  --generate-no-docker -- Generate the prebuild files without spinning pu a separate docker container (in the current environment)
  -c/--clean      -- Clean the generated files
  -i/--install-go -- Install the prebuild go files
  --install-ebpf  -- Install the prebuild ebpf files to ./ebpf-object-files for further processing
  --install-ebpf-root -- Install the prebuild ebpf files to ./ebpf-object-files-root for use in the process-agent binary
  -t/--test       -- Run tests on the upstream datadog agent
  -s/--shell      -- Launch into a shell in which the prebuild files are built
  -h/--help       -- Print this help page

USAGE
}

ACTION=""

while [ $# -gt 0 ]; do
  case $1 in
    -g|--generate)
      ACTION="generate"
      shift
    ;;
    --generate-no-docker)
      ACTION="generate-no-docker"
      shift
    ;;
    -i|--install-go)
      ACTION="install-go"
      shift
    ;;
    --install-ebpf)
      ACTION="install-ebpf"
      shift
    ;;
    --install-ebpf-root)
        ACTION="install-ebpf-root"
        shift
      ;;
    -s|--shell)
      ACTION="shell"
      shift
    ;;
    -t|--test)
      ACTION="test"
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

# First make sure all dependencies are downloaded
echo "Downloading go files"
go mod download

ALL_ARTIFACTS_DIR="$DIR/prebuild_artifacts"
GO_MOD_DEPENDENCY_DIR=$(go list -f '{{ .Dir }}' -m github.com/DataDog/datadog-agent)

# Check if the dependency was replaced
if [ "$(go list -f '{{ .Replace }}' -m github.com/DataDog/datadog-agent)" = "<nil>" ]; then
    DEPENDENCY_VERSION=$(go list -f '{{ .Version }}' -m github.com/DataDog/datadog-agent)
    REPO_PATH="https://github.com/DataDog/datadog-agent"
    SOURCE_DIR="$ALL_ARTIFACTS_DIR/checkout/$DEPENDENCY_VERSION"
else
  GO_MOD_DEPENDENCY_DIR=$(go list -f '{{ .Replace.Dir }}' -m github.com/DataDog/datadog-agent)

  if [ -d "$GO_MOD_DEPENDENCY_DIR/.git" ]; then
    echo "Running the data prebuild for a local dependency $DEPENDENCY_VERSION. Be aware that generate will not automatically pickup changes. Be sure to run -clean whenever the generated code would change."
    # The dependency is a local git repo. No need to pull or pick a version
    DEPENDENCY_VERSION="local"
    SOURCE_DIR=$GO_MOD_DEPENDENCY_DIR
  elif [ -d "$GO_MOD_DEPENDENCY_DIR" ]; then
    echo "Running for replacement git remote"
    DEPENDENCY_VERSION=$(go list -f '{{ .Replace.Version }}' -m github.com/DataDog/datadog-agent)
    REPO_PATH="https://$(go list -f '{{ .Replace.Path }}' -m github.com/DataDog/datadog-agent)"
    SOURCE_DIR="$ALL_ARTIFACTS_DIR/checkout/$DEPENDENCY_VERSION"
  else
    echo "Unknown path in go.mod: '$GO_MOD_DEPENDENCY_DIR'"
    exit 1
  fi
fi

DEPENDENCY_ARTIFACTS_DIR="$ALL_ARTIFACTS_DIR/artifacts/$DEPENDENCY_VERSION"
DOCKER_IMAGE=quay.io/stackstate/datadog_build_system-probe_x64:c3847b73

checkoutSource() {
  if [ ! -d "$SOURCE_DIR" ]; then
    echo "datadog-agent was not cloned, cloning"
    mkdir -p "$ALL_ARTIFACTS_DIR/checkout"
    GIT_VERSION=$(echo "$DEPENDENCY_VERSION" | cut -d'-' -f 3)
    (cd "$ALL_ARTIFACTS_DIR/checkout" &&
      git clone "$REPO_PATH" "$DEPENDENCY_VERSION" &&
      cd "$DEPENDENCY_VERSION" &&
      git checkout "$GIT_VERSION")
  fi
}

runPrebuildNoDocker() {
  set -x
  checkoutSource

  SOURCEDIR="$SOURCE_DIR" \
   OUTPUTDIR="$DEPENDENCY_ARTIFACTS_DIR" \
   WORKDIR="$DIR/datadog-agent-workdir" \
   $DIR/prebuild-datadog-agent-scripts/run-datadog-agent-prebuild.sh
  set +x
}

createPrebuildDockerContainer() {
  set -x

  # Remove the container if it exists
  # Clean up any stopped (or failed) containers
  docker rm -f datadog-prebuild-container || true

  docker run \
    -d \
    --name datadog-prebuild-container \
    --platform linux/amd64 \
    -e "OUTPUT_USER_ID=$(id -u "${USER}")" \
    -e "OUTPUT_GROUP_ID=$(id -g "${USER}")" \
    -v "$SOURCE_DIR":/source-datadog-agent \
    -e SOURCEDIR="/source-datadog-agent" \
    -e DD_ENABLE_RUNTIME_COMPILER=true \
    -v "$DEPENDENCY_ARTIFACTS_DIR":/output \
    -e OUTPUTDIR="/output" \
    -e WORKDIR="/workdir-datadog-agent" \
    -v "$DIR/prebuild-datadog-agent-scripts":/scripts \
    -v /proc:/host/proc \
    -e HOST_PROC=/host/proc \
    -v /sys:/host/sys \
    -e HOST_SYS=/host/sys \
    --privileged \
    --pid host \
    --cap-add all \
    "$DOCKER_IMAGE" \
    sleep infinity
  set +x
}

runPrebuildInDocker() {
  # Create a docker container if it does not exist yet
  # Runs in the context of the current directory
  # You are responsible for cleaning up the container
  set -x
  checkoutSource

   # Check if a docker container exists with the name datadog-prebuild-container
  # This is supposed to be in the running state
  if [ "$(docker ps -q -f name=datadog-prebuild-container)" = "" ]; then
    echo "No prebuild container found, creating"
    createPrebuildDockerContainer
  fi

  docker exec \
    -it \
    datadog-prebuild-container \
    "$@"
  set +x
}

if [ "$ACTION" = "generate" ]; then
  echo "Generating code"
  if [ -d "$DEPENDENCY_ARTIFACTS_DIR/gofiles" ]; then
    echo "Prebuild artifacts were already generated under $DEPENDENCY_ARTIFACTS_DIR. Skipping. To regenerate first run with --clean"
    exit 0
  fi

  mkdir -p "$DEPENDENCY_ARTIFACTS_DIR"
  runPrebuildInDocker /scripts/run-datadog-agent-prebuild.sh
elif [ "$ACTION" = "generate-no-docker" ]; then
  echo "Generating code in the current environment"
  if [ -d "$DEPENDENCY_ARTIFACTS_DIR" ]; then
    echo "Prebuild artifacts were already generated under $DEPENDENCY_ARTIFACTS_DIR. Skipping. To regenerate first run with --clean"
    exit 0
  fi

  mkdir -p "$DEPENDENCY_ARTIFACTS_DIR"
  runPrebuildNoDocker
elif [ "$ACTION" = "install-go" ]; then
  echo "Installing go files to $GO_MOD_DEPENDENCY_DIR"
  if [ ! -d "$DEPENDENCY_ARTIFACTS_DIR/gofiles" ]; then
    echo "No generated files found at $DEPENDENCY_ARTIFACTS_DIR/gofiles, please run --generate first"
    exit 1
  fi

  set -x
  chmod -R ug+w "$GO_MOD_DEPENDENCY_DIR"
  if [ "$(cp -v -a -u "$DEPENDENCY_ARTIFACTS_DIR/gofiles"/* "$GO_MOD_DEPENDENCY_DIR")" != "" ]; then
    echo "Nuking GOCACHE after changing go files, because we messed with the 'mod' directory (which gets cached)"
    rm -rf "$(go env GOCACHE)"
  fi
  set +x
elif [ "$ACTION" = "install-ebpf" ]; then
  echo "Installing ebpf files"
  if [ ! -d "$DEPENDENCY_ARTIFACTS_DIR/ebpf" ]; then
    echo "No generated files found at $DEPENDENCY_ARTIFACTS_DIR/ebpf, please run --generate first"
    exit 1
  fi

  set -x
  mkdir -p $DIR/ebpf-object-files
  rm -rf $DIR/ebpf-object-files/*
  cp -v -a "$DEPENDENCY_ARTIFACTS_DIR/ebpf"/* "$DIR/ebpf-object-files/"
  set +x
elif [ "$ACTION" = "install-ebpf-root" ]; then
  echo "Installing ebpf files as root"
  if [ ! -d "$DEPENDENCY_ARTIFACTS_DIR/ebpf" ]; then
    echo "No generated files found at $DEPENDENCY_ARTIFACTS_DIR/ebpf, please run --generate first"
    exit 1
  fi

  set -x
  mkdir -p $DIR/ebpf-object-files-root
  cp -v -a "$DEPENDENCY_ARTIFACTS_DIR/ebpf"/* "$DIR/ebpf-object-files-root/"
  sudo chown -R root:root "$DIR/ebpf-object-files-root/"
  set +x
elif [ "$ACTION" = "clean" ]; then
  echo "Cleaning prebuild files from $PREBUILD_ARTIFACTS_DIR"
  # Only delete contents, otherwise the container loses the reference to the directory
  rm -rf "$ALL_ARTIFACTS_DIR/*"
  rm -rf ebpf-object-files

  if [ -d "$DIR/ebpf-object-files-root/" ]; then
    sudo rm -rf ebpf-object-files-root
  fi
elif [ "$ACTION" = "test" ]; then
  echo "Running tests"
  runPrebuildInDocker /scripts/run-datadog-agent-test.sh
  echo "Launching generate shell"
elif [ "$ACTION" = "shell" ]; then
  echo "From the shell it is possible to run the scripts in the /scripts directory to regenerate artifacts or run tests."
  runPrebuildInDocker /bin/bash
elif [ -z "$ACTION" ]; then
  echo "No argument was passed"
  printUsage
  exit 1
else
  echo "Illegal argument $ACTION"
  printUsage
  exit 1
fi
