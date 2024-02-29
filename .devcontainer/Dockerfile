FROM artifactory.tooling.stackstate.io/docker-virtual/ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
# If you want to change the Go version, please use the update-go invoke task
ARG GO_VERSION=1.21.7
ARG GO_SHA256_LINUX_AMD64=13b76a9b2a26823e53062fa841b07087d48ae2ef2936445dc34c4ae03293702c

RUN apt-get update && apt-get install -y --no-install-recommends apt-utils && apt-get dist-upgrade -y && apt-get install -y --no-install-recommends \
        bison \
        cmake \
        curl \
        flex \
        g++ \
        gcc \
        gcc-multilib \
        git \
        libbpf-dev \
        libedit-dev \
        libelf-dev \
        libfl-dev \
        libstdc++-8-dev \
        libtinfo-dev \
        libtinfo5 \
        libxml2-dev \
        libzip-dev \
        linux-libc-dev \
        make \
        ninja-build \
        openssh-client \
        patch \
        pkg-config \
        python \
        python3-distro \
        python3-distutils \
        python3-netaddr \
        python3-setuptools \
        python3-pip \
        python3-pyroute2 \
        python3-dev \
        default-jre \
        wget \
        xsltproc \
        xz-utils \
        zsh \
        linux-headers-generic \
        vim \
        rake

# This is here for convenience to impersonate the host user. For now we run everything as root, because debugging tests can only be done as root in devcontainers
ARG HOST_USER
ARG USER_UID=1000
ARG USER_GID=$USER_UID

# Create the user
RUN groupadd --gid $USER_GID $HOST_USER \
    && useradd --uid $USER_UID --gid $USER_GID -m $HOST_USER \
    #
    # [Optional] Add sudo support. Omit if you don't need to install software after connecting.
    && apt-get update \
    && apt-get install -y sudo \
    && echo $HOST_USER ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$HOST_USER \
    && chmod 0440 /etc/sudoers.d/$HOST_USER

# install clang from the website since the package manager can change at any time
RUN wget "https://github.com/llvm/llvm-project/releases/download/llvmorg-12.0.1/clang+llvm-12.0.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz" -O /tmp/clang.tar.xz  -o /dev/null
RUN echo "6b3cc55d3ef413be79785c4dc02828ab3bd6b887872b143e3091692fc6acefe7  /tmp/clang.tar.xz" | sha256sum --check
RUN mkdir -p /opt/clang
RUN tar xf /tmp/clang.tar.xz --no-same-owner -C /opt/clang --strip-components=1
ENV PATH "/opt/clang/bin:${PATH}"

RUN python3 -m pip install -r https://raw.githubusercontent.com/DataDog/datadog-agent-buildimages/main/requirements.txt

# Install pulumi
RUN curl -fsSL https://raw.githubusercontent.com/pulumi/get.pulumi.com/f06767e3b26451439c066c94e0a907e6d6ec3d85/dist/install.sh > install-pulumi.sh
RUN echo "060d39770476f7d11de7c75dc1e1780f6492455555b36f4d3ff18f89752ebfc6  install-pulumi.sh" | sha256sum --check
RUN bash install-pulumi.sh --version 3.48.0
ENV PATH "/root/.pulumi/bin:${PATH}"
ENV PULUMI_CONFIG_PASSPHRASE "1234"

# Install Docker
# Add Docker's official GPG key:
RUN apt-get install -y --no-install-recommends ca-certificates curl gnupg
RUN install -m 0755 -d /etc/apt/keyrings
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
RUN chmod a+r /etc/apt/keyrings/docker.gpg

# Add the repository to Apt sources:
RUN echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

RUN apt-get update
RUN apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin

# Google cloud CLI for artifactory authentication
WORKDIR /root
RUN curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-463.0.0-linux-x86_64.tar.gz
RUN tar -xf google-cloud-cli-463.0.0-linux-x86_64.tar.gz
RUN ./google-cloud-sdk/install.sh --quiet --usage-reporting false

# Copy the SSH keys, if they exist
# You can also generate them later in the conainer or bind-mount them
# See https://stackoverflow.com/questions/70096208/dockerfile-copy-folder-if-it-exists-conditional-copy/70096420#70096420 for more info
RUN mkdir -p /root/.ssh
COPY [i]d_rsa.pub /root/.ssh/id_rsa.pub
COPY [i]d_rsa /root/.ssh/id_rsa

ENV GO_VERSION $GO_VERSION
ENV GOPATH=/go

RUN mkdir -p "${GOPATH}"

RUN wget -O /tmp/golang.tar.gz https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz \
  && echo "$GO_SHA256_LINUX_AMD64  /tmp/golang.tar.gz" | sha256sum --check \
  && tar -C / -xzf /tmp/golang.tar.gz \
  && rm -f /tmp/golang.tar.gz

ENV PATH "/go/bin:${PATH}"
ENV PATH "${GOPATH}/bin:${PATH}"

RUN curl -SL https://github.com/docker/compose/releases/download/v2.23.3/docker-compose-linux-x86_64 -o /usr/local/bin/docker-compose
RUN chmod +x /usr/local/bin/docker-compose

RUN go install github.com/go-delve/delve/cmd/dlv@latest

ENV HOST_PROC /host/proc
ENV HOST_SYS /host/sys
ENV HOST_ETC /host/etc
ENV DD_SYSTEM_PROBE_BPF_DIR /workspaces/agent/src/github.com/StackVista/datadog-agent-upstream-for-process-agent/pkg/ebpf/bytecode/build/
ENV STS_TEST_RUN true
ENV BPF_DEBUG true
ENV STS_DEV_CONTAINER true