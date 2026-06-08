#!/bin/bash
# Wrapper around `docker build` for stackstate-k8s-process-agent that splices
# canonical SUSE Observability OCI labels via packaging/oci-labels.sh.
#
# Replaces the previous inline docker build line in .gitlab-ci-x64.yml and
# .gitlab-ci-arm.yml so the same recipe runs identically on both arches.
#
# Required env (exported by the CI job):
#   BUILD_TAG       — full repo:tag for the local build (e.g. stackstate-k8s-process-agent:foo-amd64)
#   EBPF_SUBFOLDER  — kept as build-arg for BCI.dockerfile
#   LONG_ARCH       — kept as build-arg for BCI.dockerfile
#   SHORT_ARCH      — kept as build-arg for BCI.dockerfile
#
# Optional env:
#   BASE_IMAGE — defaults to registry.suse.com/bci/bci-micro:15.7, the
#                BCI.dockerfile `final` stage. Override only when bumping the
#                base in lockstep with BCI.dockerfile.

set -euo pipefail

base_image="${BASE_IMAGE:-registry.suse.com/bci/bci-micro:15.7}"
helper="$(dirname "$0")/oci-labels.sh"

# BUILD_TAG has the form "<repo>:<tag>". The tag is what goes into
# org.opencontainers.image.version and the ref.name suffix.
tag="${BUILD_TAG##*:}"

mapfile -t labels < <(
  "$helper" \
    --image-name stackstate-k8s-process-agent \
    --tag "$tag" \
    --title "SUSE Observability Process Agent" \
    --description "Process agent collecting per-process and per-container telemetry for SUSE Observability." \
    --component stackstate-k8s-process-agent \
    --base-image "$base_image"
)

docker build "${labels[@]}" \
  --build-arg EBPF_SUBFOLDER="$EBPF_SUBFOLDER" \
  --build-arg LONG_ARCH="$LONG_ARCH" \
  --build-arg SHORT_ARCH="$SHORT_ARCH" \
  -t "${BUILD_TAG}" \
  -f BCI.dockerfile \
  .
