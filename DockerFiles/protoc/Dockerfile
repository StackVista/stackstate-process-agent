FROM alpine:3.10

RUN apk add bash
RUN apk add protobuf-dev=3.6.1-r1
RUN apk add make go git musl-dev build-base

ADD compile-protobuf.sh /bin/compile-protobuf

ENV GOPATH /go
