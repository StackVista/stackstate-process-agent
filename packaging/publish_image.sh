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

docker login -u "${docker_user}" -p "${docker_password}" "${REGISTRY_DOCKERHUB}"
docker login -u "${quay_user}" -p "${quay_password}" "${REGISTRY_QUAY}"

for REGISTRY in "${REGISTRY_DOCKERHUB}" "${REGISTRY_QUAY}"; do
    DOCKER_TAG="${REGISTRY}/${ORGANIZATION}/${IMAGE_REPO}:${IMAGE_TAG}"

    docker tag "${BUILD_TAG}" "${DOCKER_TAG}"
    docker push "${DOCKER_TAG}"

    if [ -n "$EXTRA_TAG" ]; then
        DOCKER_EXTRA_TAG="${REGISTRY}/${ORGANIZATION}/${IMAGE_REPO}:${EXTRA_TAG}"
        docker tag "${DOCKER_TAG}" "${DOCKER_EXTRA_TAG}"
        echo "Pushing release to ${EXTRA_TAG}"
        docker push "${DOCKER_EXTRA_TAG}"
    fi
done

