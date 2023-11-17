
####################################
# Actual docker image construction #
####################################

FROM ubuntu:jammy-20230308
LABEL maintainer="StackState <info@stackstate.com>"
ENV DOCKER_STS_AGENT=true \
	DOCKER_DD_AGENT=true \
    PATH=/opt/stackstate-agent/bin/agent/:/opt/stackstate-agent/embedded/bin/:$PATH \
    CURL_CA_BUNDLE=/opt/stackstate-agent/embedded/ssl/certs/cacert.pem

# make sure we have recent dependencies
RUN apt-get update && apt-get upgrade -y \
  && apt-get install -y util-linux ncurses-bin ncurses-base libncursesw5:amd64 \
  # https://security-tracker.debian.org/tracker/CVE-2018-15686
  && apt-get install -y libudev1 libsystemd0 \
  && apt-get install -y ca-certificates \
  # https://security-tracker.debian.org/tracker/CVE-2016-2779
  && rm -f /usr/sbin/runuser \
  # https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6954
  && rm -f /usr/lib/x86_64-linux-gnu/libdb-5.3.so

# useful tools for network debugging
RUN apt-get install -y iproute2 conntrack

RUN apt-get install -y curl

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
COPY ebpf-object-files /opt/stackstate-agent/ebpf
ENV STS_SYSTEM_PROBE_BPF_DIR /opt/stackstate-agent/ebpf
ENV DD_SYSTEM_PROBE_BPF_DIR /opt/stackstate-agent/ebpf

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