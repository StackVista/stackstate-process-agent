####################################
# Actual docker image construction #
####################################

FROM ubuntu:jammy-20230308
LABEL maintainer="StackState <info@stackstate.com>"
ARG ARCH="x86_64"
ARG DOCKER_ARCH="amd64"
ARG EBPF_SUBFOLDER="x86_64"
ENV DOCKER_STS_AGENT=true \
	DOCKER_DD_AGENT=true \
    PATH=/opt/stackstate-agent/bin/agent/:/opt/stackstate-agent/embedded/bin/:$PATH \
    CURL_CA_BUNDLE=/opt/stackstate-agent/embedded/ssl/certs/cacert.pem \
    ARCH=$ARCH \
    DOCKER_ARCH=$DOCKER_ARCH \
    EBPF_SUBFOLDER=$EBPF_SUBFOLDER

# make sure we have recent dependencies
RUN apt-get update && apt-get upgrade -y \
  && apt-get install -y util-linux ncurses-bin ncurses-base libncursesw5:${DOCKER_ARCH} \
  # https://security-tracker.debian.org/tracker/CVE-2018-15686
  && apt-get install -y libudev1 libsystemd0 \
  && apt-get install -y ca-certificates \
  && apt-get install -y curl \
  && apt-get install -y wget \
  && apt-get install -y xz-utils \
  && apt-get install -y iproute2 \
  && apt-get install -y conntrack \
  # https://security-tracker.debian.org/tracker/CVE-2016-2779
  && rm -f /usr/sbin/runuser \
  # https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6954
  && rm -f /usr/lib/${ARCH}-linux-gnu/libdb-5.3.so

# install clang from the website since the package manager can change at any time
# Disabled for now because we do not do runtime compilation, but we might reenable this in the future (for debugging purpose)
#RUN wget "https://github.com/llvm/llvm-project/releases/download/llvmorg-12.0.1/clang+llvm-12.0.1-${DOCKER_ARCH}-linux-gnu-ubuntu-16.04.tar.xz" -O /tmp/clang.tar.xz  -o /dev/null
#RUN echo "6b3cc55d3ef413be79785c4dc02828ab3bd6b887872b143e3091692fc6acefe7  /tmp/clang.tar.xz" | sha256sum --check
#RUN mkdir -p /opt/clang
#RUN tar xf /tmp/clang.tar.xz --no-same-owner -C /opt/clang --strip-components=1
#ENV PATH "/opt/clang/bin:${PATH}"
#
#RUN mkdir -p /opt/datadog-agent/embedded/bin
#RUN ln -s $(which clang) /opt/datadog-agent/embedded/bin/clang-bpf
#RUN ln -s $(which llc) /opt/datadog-agent/embedded/bin/llc-bpf

# cleanup image's filesystem
RUN rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY DockerFiles/agent/probe.sh /
COPY DockerFiles/agent/entrypoint/init-process.sh /

# Prepare for running without root
# - Create a stackstate-agent:root user and give it permissions on relevant folders
# - Remove the /var/run -> /run symlink and create a legit /var/run folder
# as some docker versions re-create /run from zero at container start

RUN mkdir -p /etc/stackstate-agent/ && mkdir -p /var/log/stackstate-agent/

RUN  adduser --system --no-create-home --disabled-password --ingroup root stackstate-agent \
 && chown -R stackstate-agent:root /etc/stackstate-agent/ /var/log/stackstate-agent/ \
 && chmod g+r,g+w,g+X -R /etc/stackstate-agent/ /var/log/stackstate-agent/ \
 && chmod 755 /probe.sh /init-process.sh


# Copy eBPF probes
COPY ebpf-object-files/${EBPF_SUBFOLDER} /opt/stackstate-agent/ebpf
ENV STS_SYSTEM_PROBE_BPF_DIR=/opt/stackstate-agent/ebpf
ENV DD_SYSTEM_PROBE_BPF_DIR=/opt/stackstate-agent/ebpf

#   - copy default config files
COPY DockerFiles/agent/stackstate*.yaml /etc/stackstate-agent/

# Copy agent
COPY process-agent /opt/stackstate-agent/bin/agent/

WORKDIR /opt/stackstate-agent/bin/agent

HEALTHCHECK --interval=2m --timeout=5s --retries=2 \
  CMD ["/probe.sh"]

# Leave following directories RW to allow use of kubernetes readonlyrootfs flag
VOLUME ["/etc/stackstate-agent", "/var/log/stackstate", "/tmp"]

CMD ["/init-process.sh"]