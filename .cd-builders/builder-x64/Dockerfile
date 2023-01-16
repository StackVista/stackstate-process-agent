# Source: https://github.com/DataDog/datadog-agent-buildimages/blob/8e9431f1e0ad3fc5d902b81c5949040f6c7f2d85/system-probe_x64/Dockerfile

FROM debian:buster

ARG DEBIAN_FRONTEND=noninteractive

# We need up-to-date kernel headers to be able to use newly available eBPF helpers in programs.
RUN echo "deb http://deb.debian.org/debian buster-backports main" | tee -a /etc/apt/sources.list

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
        $(apt-cache search --names-only linux-headers-5.* | \
          cut -d " " -f 1 | \
          grep "\-common$" | \
          sed -rn 's/(.*deb10\.)([0-9]+)-common/\2 \0 \1\2-amd64/p' | \
          sort -gr | \
          head -n 1 | \
          cut -f 2-3 -d " ") \
        linux-libc-dev \
        make \
        ninja-build \
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
        wget \
        xz-utils


ADD setup-clang-buildtime.sh ./
RUN mkdir -p /opt/clang
RUN ./setup-clang-buildtime.sh /opt/clang
ENV PATH "/opt/clang/bin:${PATH}"


ENV STACKSTATE_EMBEDDED_PATH=/opt/stackstate-agent/embedded
RUN mkdir -p ${STACKSTATE_EMBEDDED_PATH}

ADD setup-clangllvm-runtime.sh ./
RUN ./setup-clangllvm-runtime.sh ${STACKSTATE_EMBEDDED_PATH}


# Setup process-agent build tooling

COPY requirements.txt /
RUN python3 -m pip install wheel
RUN python3 -m pip install -r requirements.txt

#ARG GIMME_GO_VERSION=1.18.7
ARG GIMME_GO_VERSION=1.17.13

ENV GIMME_GO_VERSION $GIMME_GO_VERSION
ENV GOPATH=/go

RUN wget -O /bin/gimme https://raw.githubusercontent.com/travis-ci/gimme/v1.5.4/gimme
RUN echo "03b295636d4e22870b6f6e9bc06a71d65311ae90d3d48cbc7071f82dd5837fbc  /bin/gimme" | sha256sum --check
RUN chmod +x /bin/gimme
RUN gimme $GIMME_GO_VERSION

ENV PATH "${GOPATH}/bin:${PATH}"

RUN apt-get install -y --no-install-recommends rake jq unzip

ARG PROTOC_VERSION=3.6.1
ENV PROTOC_VERSION $PROTOC_VERSION

RUN curl -OL https://github.com/google/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip
RUN echo "6003de742ea3fcf703cfec1cd4a3380fd143081a2eb0e559065563496af27807 protoc-${PROTOC_VERSION}-linux-x86_64.zip" | sha256sum --check
RUN unzip protoc-${PROTOC_VERSION}-linux-x86_64.zip -d /usr/local

# Configure image runtime

COPY ./entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
