#!/usr/bin/env bash

export COMPOSE_INTERACTIVE_NO_CLI=1

export CURRENT_BRANCH=${GITHUB_HEAD_REF:-${GITHUB_REF_NAME:-${CI_COMMIT_REF_NAME:-$(git rev-parse --abbrev-ref HEAD)}}}
echo "CURRENT_BRANCH set to: $CURRENT_BRANCH"

# /proc/net/route contains the default gateway in little-endian hexadecimal.
hexaddr=$(awk '$2 == "00000000" {print $3}' /proc/net/route | head -n 1)
gateway_octets=()
for ((i = ${#hexaddr}; i > 0; i -= 2)); do
  gateway_octets+=("0x${hexaddr:i-2:2}")
done
printf -v ipaddr "%d." "${gateway_octets[@]}"
ipaddr=${ipaddr%.}

export DOCKER_HOST_IP=$ipaddr
echo "DOCKER_HOST_IP set to: ${DOCKER_HOST_IP}"
