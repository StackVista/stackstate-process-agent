#!/usr/bin/env bash

# Okay, here it goes: The process agent depends on the datadog agent, which:
# - for some modules (EBPF) uses go:generate which needs to be run to even build the dependency.
# - for some other modules generate EBPF code, which we need but is not part of the regular go build
# This file makes sure those prebuild steps (go:generate and ebpf files) get built and installed.

set -e

DIR="${BASH_SOURCE%/*}"
if [ ! -d "$DIR" ] || [ "$DIR" = "." ]; then DIR="$PWD"; fi

printUsage() {
  cat << USAGE

Usage: ./prebuild-datadog-agent.sh --generate|--clean|--shell|--install-go|--help

This script run the prebuild steps for the datadog agent dependency. Those steps are not automatically invoked by the go build.
  -g/--generate   -- Generate the prebuild files by running inside a docker container
  --generate-no-docker -- Generate the prebuild files without spinning pu a separate docker container (in the current environment)
  -c/--clean      -- Clean the generated files
  -i/--install-go -- Install the prebuild go files
  --install-ebpf  -- Install the prebuild ebpf files to ./ebpf-object-files for further processing
  --install-ebpf-from-dep  -- Install the prebuild ebpf files from the go sum dependency. Requires root, because typically those files are generated as root user.
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
    --install-ebpf-from-dep)
      ACTION="install-ebpf-from-dep"
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
go mod download

# Check if the dependency was replaced, if not return an error
if [ "$(go list -f '{{ .Replace }}' -m github.com/DataDog/datadog-agent)" = "<nil>" ]; then
  echo "We cannot build against upstream datadog we need to replace it with a local copy." >&2
  exit 1
fi

ALL_ARTIFACTS_DIR="$DIR/prebuild_artifacts"
GO_MOD_DEPENDENCY_DIR=$(go list -f '{{ .Replace.Dir }}' -m github.com/DataDog/datadog-agent)
if [ -d "$GO_MOD_DEPENDENCY_DIR/.git" ]; then
  # The dependency is a local git repo. No need to pull or pick a version
  DEPENDENCY_VERSION="local"
  SOURCE_DIR=$GO_MOD_DEPENDENCY_DIR
elif [ -d "$GO_MOD_DEPENDENCY_DIR" ]; then
  DEPENDENCY_VERSION=$(go list -f '{{ .Replace.Version }}' -m github.com/DataDog/datadog-agent)
  REPO_PATH="https://$(go list -f '{{ .Replace.Path }}' -m github.com/DataDog/datadog-agent)"
  SOURCE_DIR="$ALL_ARTIFACTS_DIR/checkout/$DEPENDENCY_VERSION"
else
  echo "Unknown path in go.mod: '$GO_MOD_DEPENDENCY_DIR'"
  exit 1
fi
echo "[DATADOG_SOURCE_DIR=$GO_MOD_DEPENDENCY_DIR]"

# obtain the docker image from datadog repo
source $GO_MOD_DEPENDENCY_DIR/sts_tests/docker_image.sh
DEPENDENCY_ARTIFACTS_DIR="$ALL_ARTIFACTS_DIR/artifacts/$DEPENDENCY_VERSION"

checkoutSource() {
  if [ ! -d "$SOURCE_DIR" ]; then
    echo "datadog-agent was not cloned at ${SOURCE_DIR}, cloning"
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

runPrebuildInDocker() {
  set -x
  checkoutSource

  docker run \
    --platform linux/amd64 \
    -e "OUTPUT_USER_ID=$(id -u "${USER}")" \
    -e "OUTPUT_GROUP_ID=$(id -g "${USER}")" \
    -v "$SOURCE_DIR":/source-datadog-agent \
    -e SOURCEDIR="/source-datadog-agent" \
    -v "$DEPENDENCY_ARTIFACTS_DIR":/output \
    -e OUTPUTDIR="/output" \
    -e WORKDIR="/workdir-datadog-agent" \
    -v "$DIR/prebuild-datadog-agent-scripts":/scripts \
    -v /proc:/host/proc \
    -e HOST_PROC=/host/proc \
    -v /sys:/host/sys \
    -e HOST_SYS=/host/sys \
    -v /etc:/host/etc:ro \
    -e HOST_ETC=/host/etc \
    -v /var/run/docker.sock:/var/run/docker.sock \
    --network host \
    --privileged \
    --pid host \
    --cap-add all \
     --rm -i -t \
    "$@"
  set +x
}

if [ "$ACTION" = "generate" ]; then
  echo "- Generating ebpf artifacts and go files inside docker container"
  if [ -d "$DEPENDENCY_ARTIFACTS_DIR/gofiles" ]; then
    echo "- Prebuild artifacts were already generated under $DEPENDENCY_ARTIFACTS_DIR. Skipping. To regenerate first run with --clean"
    exit 0
  fi

  mkdir -p "$DEPENDENCY_ARTIFACTS_DIR"
  runPrebuildInDocker "$DOCKER_IMAGE" /scripts/run-datadog-agent-prebuild.sh
elif [ "$ACTION" = "generate-no-docker" ]; then
  echo "- Generating ebpf artifacts and go files in the current environment"
  if [ -d "$DEPENDENCY_ARTIFACTS_DIR" ]; then
    echo "- Prebuild artifacts were already generated under $DEPENDENCY_ARTIFACTS_DIR. Skipping. To regenerate first run with --clean"
    exit 0
  fi

  mkdir -p "$DEPENDENCY_ARTIFACTS_DIR"
  runPrebuildNoDocker
elif [ "$ACTION" = "install-go" ]; then
  echo "- Moving go files from '$DEPENDENCY_ARTIFACTS_DIR/gofiles' to '$GO_MOD_DEPENDENCY_DIR'"
  if [ ! -d "$DEPENDENCY_ARTIFACTS_DIR/gofiles" ]; then
    echo "- No generated files found at $DEPENDENCY_ARTIFACTS_DIR/gofiles, please run --generate first"
    exit 1
  fi

  # Checks if the directory is writable by the current user.
  # We need to write the go files to the directory where the datadog-agent dependency is located.
  if [ ! -w "$GO_MOD_DEPENDENCY_DIR" ]; then
    # try to do it by ourself if we have permissions
    if ! chmod -R ug+w "$GO_MOD_DEPENDENCY_DIR" 2>/dev/null; then
      echo "Error: Directory '$GO_MOD_DEPENDENCY_DIR' is not writable by user '$(whoami)'." >&2
      echo "Please fix the permissions before running this script. You can likely fix this by running:" >&2
      echo "  sudo chmod -R ug+w '$GO_MOD_DEPENDENCY_DIR'" >&2
      exit 1
    fi
  fi

  set -x
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
elif [ "$ACTION" = "install-ebpf-from-dep" ]; then
  echo "Installing ebpf files from the dependent go module"
  if [ ! -d "$GO_MOD_DEPENDENCY_DIR/pkg/ebpf/bytecode/build" ]; then
    echo "No generated files found at $GO_MOD_DEPENDENCY_DIR/pkg/ebpf/bytecode/build, please make sure the files are generated"
    exit 1
  fi

  set -x
  mkdir -p $DIR/ebpf-object-files
  rm -rf $DIR/ebpf-object-files/*
  sudo cp -v -a "$GO_MOD_DEPENDENCY_DIR/pkg/ebpf/bytecode/build"/* "$DIR/ebpf-object-files/"
  CURRENT_USER=$(whoami)
  sudo chown "$CURRENT_USER:$CURRENT_USER" -R "$DIR/ebpf-object-files/"
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
  rm -rf "$ALL_ARTIFACTS_DIR"
  rm -rf ebpf-object-files

  if [ -d "$DIR/ebpf-object-files-root/" ]; then
    sudo rm -rf ebpf-object-files-root
  fi
elif [ "$ACTION" = "shell" ]; then
  echo "Launching generate shell"
  echo "From the shell it is possible to run the scripts in the /scripts directory to regenerate artifacts or run tests."
  runPrebuildInDocker -it "$DOCKER_IMAGE" /bin/bash
elif [ -z "$ACTION" ]; then
  echo "No argument was passed"
  printUsage
  exit 1
else
  echo "Illegal argument $ACTION"
  printUsage
  exit 1
fi
