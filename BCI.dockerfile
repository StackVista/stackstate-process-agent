############################
# 1. Build / packaging step#
############################
FROM registry.suse.com/bci/bci-base:15.6 AS builder

ARG LONG_ARCH="x86_64"
ARG SHORT_ARCH="amd64"
ARG EBPF_SUBFOLDER="x86_64"

# Re-use the same env vars the original Dockerfile exported
ENV DOCKER_STS_AGENT=true \
    DOCKER_DD_AGENT=true \
    PATH=/opt/stackstate-agent/bin/agent/:/opt/stackstate-agent/embedded/bin/:$PATH \
    CURL_CA_BUNDLE=/opt/stackstate-agent/embedded/ssl/certs/cacert.pem \
    LONG_ARCH=${LONG_ARCH} \
    SHORT_ARCH=${SHORT_ARCH} \
    EBPF_SUBFOLDER=${EBPF_SUBFOLDER}

# ----------------------------------------------------------------------
# 1.1 Create a chroot where everything will be installed
# ----------------------------------------------------------------------
RUN mkdir /chroot

# ----------------------------------------------------------------------
# 1.2 Install the packages we need **into the chroot only**
# ----------------------------------------------------------------------
#   –--root /chroot tells zypper to install into /chroot instead of “real” root
#   –-n      answers “yes” to all questions (non-interactive)
#   –clean   removes downloaded RPMs afterwards
RUN zypper -n ref && \
    zypper -n --root /chroot install \
        util-linux \
        ncurses \
        libncurses6 \
        systemd-libs \
        libudev1 \
        ca-certificates \
        curl \
        wget \
        xz \
        iproute2 \
        conntrack-tools && \
    zypper -n --root /chroot clean --all

# ----------------------------------------------------------------------
# 1.3 Prepare application directories inside the chroot
# ----------------------------------------------------------------------
RUN mkdir -p /chroot/opt/stackstate-agent/bin/agent \
    && mkdir -p /chroot/etc/stackstate-agent \
    && mkdir -p /chroot/var/log/stackstate-agent

# ----------------------------------------------------------------------
# 1.4 Copy our application bits into the chroot
# ----------------------------------------------------------------------
COPY ebpf-object-files/${EBPF_SUBFOLDER} /chroot/opt/stackstate-agent/ebpf
COPY DockerFiles/agent/stackstate*.yaml   /chroot/etc/stackstate-agent/
COPY process-agent                        /chroot/opt/stackstate-agent/bin/agent/
COPY DockerFiles/agent/probe.sh           /chroot/
COPY DockerFiles/agent/entrypoint/init-process.sh /chroot/

# ----------------------------------------------------------------------
# 1.5 Permissions and small clean-ups inside the chroot
# ----------------------------------------------------------------------
RUN chmod 755 /chroot/probe.sh /chroot/init-process.sh && \
    chroot /chroot useradd -r -s /sbin/nologin -g root stackstate-agent && \
    chroot /chroot chown -R stackstate-agent:root /etc/stackstate-agent /var/log/stackstate-agent && \
    rm -rf /chroot/var/cache/zypp /chroot/tmp/* /chroot/var/tmp/*

############################
# 2. Final, tiny run image #
############################
FROM registry.suse.com/bci/bci-micro:15.6

ARG EBPF_SUBFOLDER="x86_64"

ENV DOCKER_STS_AGENT=true \
    DOCKER_DD_AGENT=true \
    PATH=/opt/stackstate-agent/bin/agent/:/opt/stackstate-agent/embedded/bin/:$PATH \
    CURL_CA_BUNDLE=/opt/stackstate-agent/embedded/ssl/certs/cacert.pem \
    STS_SYSTEM_PROBE_BPF_DIR=/opt/stackstate-agent/ebpf \
    DD_SYSTEM_PROBE_BPF_DIR=/opt/stackstate-agent/ebpf

# Copy *only* the prepared /chroot filesystem from the builder image
COPY --from=builder /chroot/ /

# The user, permissions, etc. were already created inside /chroot
# so there is nothing more to do here.

# Volumes that must stay read/write for kubernetes “readOnlyRootFS” setups
VOLUME ["/etc/stackstate-agent", "/var/log/stackstate", "/tmp"]

WORKDIR /opt/stackstate-agent/bin/agent

HEALTHCHECK --interval=2m --timeout=5s --retries=2 \
  CMD ["/probe.sh"]

CMD ["/init-process.sh"]