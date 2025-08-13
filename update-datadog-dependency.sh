#!/bin/bash

set -e

printUsage() {
  cat << USAGE

Usage: ./update-datadog-dependency.sh --local <path>|--branch <branch>|--help

This script will update go.mod to point to a different remote
  -l/--local <path>    -- Use a local directory as dependency for all github.com/DataDog/datadog-agent modules
  -b/--branch [branch] -- Use the given branch of github.com/StackVista/datadog-agent-upstream-for-process-agent as a dependency for all github.com/DataDog/datadog-agent modules
  -h/--help            -- Print this help page

USAGE
}

apply_replaces_for_all_modules() {
  local target="$1" # can be a path (local case) or a commit (branch case)
  local mode="$2"   # "local" or "branch"

  # Collect all modules that match github.com/DataDog/datadog-agent
  MODULES=$(go list -m all | grep '^github.com/DataDog/datadog-agent') || true

  if [ -z "${MODULES}" ]; then
    echo "No github.com/DataDog/datadog-agent modules found with 'go list -m all'"
    exit 1
  fi
   
  if [ "$mode" = "branch" ]; then
    # `go mod edit -replace github.com/DataDog/datadog-agent=github.com/StackVista/datadog-agent-upstream-for-process-agent@a64e3e351860fe643f9f426275d2311db760974a`
    # The command above will produce the following output in the `go.mod` file:
    # `replace github.com/DataDog/datadog-agent => github.com/StackVista/datadog-agent-upstream-for-process-agent a64e3e351860fe643f9f426275d2311db760974a`
    # 
    # This is not a valid format, and we call another `go mod edit -replace` go will tell us:
    # `version "a64e3e351860fe643f9f426275d2311db760974a" invalid: must be of the form v1.2.3`
    # So in order to fix it we should call `go mod tidy`.
    #
    # The issue is that calling go mod tidy in a loop for 60/70 modules after each go mod replace could require some time
    # so what we want to do is to craft immediately the line to add in the go.mod with the right format.
    # 
    # `replace github.com/DataDog/datadog-agent => github.com/StackVista/datadog-agent-upstream-for-process-agent v0.0.0-20250812091526-a64e3e351860`
    # to do that we need to extract the pseudo version.
    # 
    # `pseudoVersion` is in this form `v0.0.0-20250808083223-d90e66612b92`
    pseudoVersion=$(go list -m -json "github.com/StackVista/datadog-agent-upstream-for-process-agent@${target}" | jq -r .Version)
    echo "Using pseudo version '${pseudoVersion}' for all modules"
  fi


  # -r to avoid to interpret backslashes
  while IFS= read -r line; do
    # line format is: <module> <version>
    # so we take only the module
    # Example: github.com/DataDog/datadog-agent/pkg/util
    mod=$(echo "$line" | awk '{print $1}')
    if [ -z "$mod" ]; then
      echo "'$mod' is not a valid module"
      exit 1
    fi

    # Example: github.com/DataDog/datadog-agent/pkg/util => tailPath `/pkg/util`
    tailPath="${mod#github.com/DataDog/datadog-agent}"
    
    if [ "$mode" = "local" ]; then
      # Example:
      # target: /tmp/my-datadog, tailPath: /pkg/util
      # replaceTarget: /tmp/my-datadog/pkg/util
      replaceTarget="${target}${tailPath}"
    else
      # Example:
      # tailPath: /pkg/util
      # pseudoVersion: v0.0.0-20250808083223-d90e66612b92
      # replaceTarget: github.com/StackVista/datadog-agent-upstream-for-process-agent/pkg/util@v0.0.0-20250808083223-d90e66612b92
      replaceTarget="github.com/StackVista/datadog-agent-upstream-for-process-agent${tailPath}@${pseudoVersion}"
    fi
    echo "Replace '$mod' => '${replaceTarget}'"
    go mod edit -replace "$mod=${replaceTarget}"
  done <<EOF
${MODULES}
EOF
  # Do the go mod tidy just once at the end
  go mod tidy
}
while [ $# -gt 0 ]; do
  case $1 in
    -l|--local)
      shift
      LOCAL_PATH="$1"
      if [ -z "${LOCAL_PATH}" ]; then
        echo "Error: missing local path"
        exit 1
      fi
      apply_replaces_for_all_modules "${LOCAL_PATH}" "local"
      exit 0
    ;;
    -b|--branch)
      shift
      BRANCH="${1}"
      echo "Using branch '${BRANCH}'"

      # Branch names that contains a slash are not valid in go.mod, so we need to use the commit hash
      # See: https://github.com/golang/go/issues/32955
      # We need the `tail -n 1` because in case of merge commits we could have 2 commit hashes in the output, just take the last one.
      COMMIT=$(git ls-remote https://github.com/StackVista/datadog-agent-upstream-for-process-agent.git "${BRANCH}" | tail -n 1 | awk '{print $1}')
      if [ -z "${COMMIT}" ]; then
        echo "Error: commit not found for ${BRANCH}"
        exit 1
      fi
      echo "Derived commit '${COMMIT}'"
      apply_replaces_for_all_modules "${COMMIT}" "branch"
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
