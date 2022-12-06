#!/usr/bin/env bash

download_and_check_sha256sum () {
  local URL=$1
  local TARGET=$2
  local CHECKSUM=$3
  wget $1 --no-verbose -O $2
  echo $3 $2  | sha256sum --check
}

set -ex

TARGET_DIR="$1"
ls ${TARGET_DIR}

download_and_check_sha256sum "https://github.com/llvm/llvm-project/releases/download/llvmorg-12.0.1/clang+llvm-12.0.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz" \
                              /tmp/clang.tar.xz "6b3cc55d3ef413be79785c4dc02828ab3bd6b887872b143e3091692fc6acefe7"

tar xf /tmp/clang.tar.xz --no-same-owner -C ${TARGET_DIR} --strip-components=1
