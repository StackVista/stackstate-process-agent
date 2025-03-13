#!/bin/bash

# Okay, here it goes: The process agent depends on the datadog agent, which:
# - for some modules (EBPF) uses go:generate which needs to be run to even build the dependency.
# - for some other modules generate EBPF code, which we need but is not part of the regular go build
# This file makes sure those prebuild steps (go:generate and ebpf files) get built and installed.

set -e

printUsage() {
  cat << USAGE

Usage: ./update-datadog-dependency.sh --local <path>|--branch <branch>|--help

This script will update go.mod to point to a different remote
  -l/--local           -- Use a local directory as dependency
  -b/--branch [branch] -- Use the given branch of github.com/StackVista/datadog-agent-upstream-for-process-agent as a dependency, defaults to stackstate-7.49.1
  -h/--help            -- Print this help page

USAGE
}

ACTION=""
BRANCH="stackstate-7.49.1"
while [ $# -gt 0 ]; do
  case $1 in
    -l|--local)
      shift
      go mod edit -replace "github.com/DataDog/datadog-agent=$1"
      go mod tidy
      exit 0
    ;;
    -b|--branch)
      shift
      BRANCH="${1}"
      echo "Using branch '${BRANCH}'"

      # Branch names that contains a slash are not valid in go.mod, so we need to use the commit hash
      # See: https://github.com/golang/go/issues/32955
      COMMIT=$(git ls-remote https://github.com/StackVista/datadog-agent-upstream-for-process-agent.git "${BRANCH}" | awk '{print $1}')
      if [ -z "${COMMIT}" ]; then
        echo "Error: commit not found for ${BRANCH}"
        exit 1
      fi
      echo "Derived commit '${COMMIT}'"
      go mod edit -replace "github.com/DataDog/datadog-agent=github.com/StackVista/datadog-agent-upstream-for-process-agent@${COMMIT}"
      go mod tidy
      exit 0
    ;;
    -h|--help)
      printUsage
      exit 0
    ;;
    *)
      echo "Unknown flag"
      printUsage
      exit 1
    ;;
  esac
done


