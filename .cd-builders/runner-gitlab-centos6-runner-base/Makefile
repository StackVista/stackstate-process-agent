RUNTIMETAG := $(shell date +%Y%m%d)
BASE_CENTOS_IMAGE_VERSION ?= centos6_20220211

build:
	docker build --build-arg BASE_CENTOS_IMAGE_VERSION=$(BASE_CENTOS_IMAGE_VERSION) -t docker.io/stackstate/stackstate-process-agent-runner-gitlab:centos6-runner-base-$(RUNTIMETAG) .
push:
	docker push docker.io/stackstate/stackstate-process-agent-runner-gitlab:centos6-runner-base-$(RUNTIMETAG)

