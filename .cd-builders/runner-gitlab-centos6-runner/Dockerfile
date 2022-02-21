ARG BASE_RUNNER_IMAGE_VERSION
FROM docker.io/stackstate/stackstate-process-agent-runner-gitlab:${BASE_RUNNER_IMAGE_VERSION}

RUN yum install -y rsync \
    && /bin/bash -l -c "gem install rake fpm deb-s3" \
    && curl https://glide.sh/get | sh

# Install clang and llvm version 8
# Using build for sles11 because the versions built for other distros target glibcs that are too new to be used from this image
ENV CLANG_VERSION=8.0.0
RUN curl -LO https://releases.llvm.org/${CLANG_VERSION}/clang+llvm-${CLANG_VERSION}-x86_64-linux-sles11.3.tar.xz && \
    tar -xf clang+llvm-${CLANG_VERSION}-x86_64-linux-sles11.3.tar.xz --no-same-owner --strip 1 -kC /usr/ && \
    rm clang+llvm-${CLANG_VERSION}-x86_64-linux-sles11.3.tar.xz

# To build the EBPF code we need kernel headers for Linux 4.9
RUN rm -r /usr/src/kernels/* && \
    curl -Sl -O https://dd-agent-omnibus.s3.amazonaws.com/kernel-4.9-headers-rpm-x64.tgz && \
    tar xf kernel-4.9-headers-rpm-x64.tgz --no-same-owner --strip 1 -C /usr && \
    rm kernel-4.9-headers-rpm-x64.tgz

# Update GCC: CentOS6 gcc-4.4 is a little too far behind what we use with the debian builder
RUN curl -o /etc/yum.repos.d/devtools-1.1.repo https://people.centos.org/tru/devtools-1.1/devtools-1.1.repo
RUN yum --enablerepo=testing-1.1-devtools-6 -y install devtoolset-1.1-gcc devtoolset-1.1-gcc-c++

ENV CC=/opt/centos/devtoolset-1.1/root/usr/bin/gcc
ENV CPP=/opt/centos/devtoolset-1.1/root/usr/bin/cpp
ENV CXX=/opt/centos/devtoolset-1.1/root/usr/bin/c++

SHELL ["/bin/bash", "-c"]