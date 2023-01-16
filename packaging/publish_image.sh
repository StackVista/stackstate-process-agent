#!/bin/sh

set -xe

BUILD_TAG="${1}"
IMAGE_REPO="${2}"
IMAGE_TAG="${3}"
EXTRA_TAG="${4}"
REGISTRY_DOCKERHUB="docker.io"
REGISTRY_QUAY="quay.io"
ORGANIZATION="stackstate"

echo "IMAGE_TAG=${IMAGE_TAG}"
echo "IMAGE_REPO=${IMAGE_REPO}"

PUBLISHED=""

docker_tag_and_push () {
  docker tag "${BUILD_TAG}" "$1"
  docker push "$1"
  PUBLISHED="$PUBLISHED $1"
}

for REGISTRY in "${REGISTRY_DOCKERHUB}" "${REGISTRY_QUAY}"; do
    DOCKER_TAG="${REGISTRY}/${ORGANIZATION}/${IMAGE_REPO}:${IMAGE_TAG}"
    docker_tag_and_push "${DOCKER_TAG}"

    if [ -n "$EXTRA_TAG" ]; then
        DOCKER_EXTRA_TAG="${REGISTRY}/${ORGANIZATION}/${IMAGE_REPO}:${EXTRA_TAG}"
        docker_tag_and_push "${DOCKER_EXTRA_TAG}"
    fi
done

set +x
echo ""
echo "Published images:"
for tag in ${PUBLISHED}
do
  echo "        $tag"
done
