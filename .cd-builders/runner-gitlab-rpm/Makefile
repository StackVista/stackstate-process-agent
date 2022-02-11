RUNTIMETAG := $(shell date +%Y%m%d)
BASE_RUNNER_IMAGE_VERSION ?= centos6-runner-base_latest

build:
	docker build --build-arg BASE_RUNNER_IMAGE_VERSION=$(BASE_RUNNER_IMAGE_VERSION) -t stackstate/stackstate-process-agent-runner-gitlab:centos6-runner-$(RUNTIMETAG) .

push:
	docker push stackstate/stackstate-process-agent-runner-gitlab:centos6-runner-$(RUNTIMETAG)
