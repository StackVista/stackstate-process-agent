ARG BASE_CENTOS_IMAGE_VERSION
FROM stackstate/stackstate-process-agent-runner-gitlab:$BASE_CENTOS_IMAGE_VERSION

ENV SYSTEMD_VERSION=219
ENV GIT_VERSION=2.21.0
ENV PYTHON_VERSION=2.7.15
ENV GOLANG_VERSION=1.17.7
ENV RBENV_VERSION=2.4.4
ENV BUNDLER_VERSION=1.15.3
ENV CONDA_PATH=/root/miniconda3
ENV DD_CONDA_VERSION=4.7.10

RUN yum -y install curl-devel expat-devel gettext-devel perl-ExtUtils-MakeMaker \
                   gcc make openssl-devel bzip2 bzip2-devel readline-devel \
                   zlib-devel patch gcc-c++ file rpm-build openssh-clients byacc

# Provide systemd header files needed to build the agent systemd module (journald log collector)
RUN curl "https://codeload.github.com/systemd/systemd/tar.gz/v$SYSTEMD_VERSION" -o "systemd-$SYSTEMD_VERSION.tar.gz" \
    && tar xzf systemd-$SYSTEMD_VERSION.tar.gz \
    && mv systemd-$SYSTEMD_VERSION/src/systemd/ /usr/include/

# Git
RUN curl -OL https://www.kernel.org/pub/software/scm/git/git-2.10.1.tar.gz
# --no-same-owner: git tarball has a file with UID 110493 which makes pulling this image fail, because we use docker user namespacing and we can't have >65K UIDs.
RUN tar xzf git-2.10.1.tar.gz --no-same-owner
RUN cd git-2.10.1 && make prefix=/usr/local all
RUN cd git-2.10.1 && make prefix=/usr/local install
RUN rm -rf git-2.10.1 git-2.10.1.tar.gz

RUN git config --global user.email "gitlab@stackstate" && git config --global user.name "Gitlab Stackstate"

ENV PATH=$PATH:/usr/src/git/bin

# Conda
RUN curl -sL -o ~/miniconda.sh https://repo.anaconda.com/miniconda/Miniconda3-${DD_CONDA_VERSION}-Linux-x86_64.sh
RUN bash ~/miniconda.sh -b
COPY ./conda.sh /etc/profile.d/
ENV PATH "${CONDA_PATH}/bin:${PATH}"

ENV PKG_CONFIG_LIBDIR $PKG_CONFIG_LIBDIR:$CONDA_PATH/lib/pkgconfig

# Setup pythons
RUN conda create -n processagentpy3 python python=3.8

# CONDA prep
RUN conda init bash

# Golang
RUN curl -sL -o /bin/gimme https://raw.githubusercontent.com/travis-ci/gimme/master/gimme
RUN chmod +x /bin/gimme
RUN GIMME_DEBUG=1 gimme $GOLANG_VERSION
COPY ./gobin.sh /etc/profile.d/

ENV GOPATH /go
ENV GOBIN /root/.gimme/versions/go"$GOLANG_VERSION".linux.amd64/bin
ENV PATH="$HOME"/bin:/root/.gimme/versions/go"$GOLANG_VERSION".linux.amd64/bin:/usr/local/go/bin:/go/src/github.com/bin:$PATH

RUN mkdir -p $GOPATH $HOME/bin/ /usr/local/go/bin \
    && echo $PATH && go version

WORKDIR $GOPATH

RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh

RUN go get -u golang.org/x/lint/golint

# Ruby + Rake
COPY ./rvm/gpg-keys /gpg-keys
RUN gpg --import /gpg-keys/*
RUN rm -rf /gpg-keys
RUN curl -sSL https://get.rvm.io | bash -s stable --version latest-1.29

RUN mkdir -p /usr/local/etc \
    && { \
    echo 'install: --no-document'; \
    echo 'update: --no-document'; \
    } >> /usr/local/etc/gemrc

RUN /bin/bash -l -c "rvm requirements"
RUN /bin/bash -l -c "rvm install 2.4.2 && rvm cleanup all"
RUN /bin/bash -l -c "gem install bundler --no-document"

# Setup git
RUN git config --global user.email "gitlab@stackstate" && git config --global user.name "Gitlab Stackstate"

# Pip install deps
RUN pip install awscli==1.16.314 boto3==1.17.68 sts-rpm-s3

# Yum
RUN yum -y install net-snmp-devel python-deltarpm yum-utils libtool rpm-sign createrepo

ADD rpmmacros /root/.rpmmacros

ENTRYPOINT ["/entrypoint.sh"]
