#!/usr/bin/env bash

download_and_check_sha256sum () {
  local URL=$1
  local TARGET=$2
  local CHECKSUM=$3
  wget $1 --no-verbose -O $2
  echo $3 $2  | sha256sum --check
}

set -ex

TARGET_DIR=$1
ls $1

mkdir /tmp/clangbuild && cd /tmp/clangbuild

download_and_check_sha256sum https://github.com/llvm/llvm-project/releases/download/llvmorg-11.0.1/clang-11.0.1.src.tar.xz \
                             clang.src.tar.xz 73f572c2eefc5a155e01bcd84815751d722a4d3925f53c144acfb93eeb274b4d
download_and_check_sha256sum https://github.com/llvm/llvm-project/releases/download/llvmorg-11.0.1/llvm-11.0.1.src.tar.xz \
                             llvm.src.tar.xz ccd87c254b6aebc5077e4e6977d08d4be888e7eb672c6630a26a15d58b59b528

mkdir clang && tar xf clang.src.tar.xz --strip-components=1 --no-same-owner -C clang
mkdir llvm && tar xf llvm.src.tar.xz --strip-components=1 --no-same-owner -C llvm

mkdir build && cd build
cmake -DLLVM_ENABLE_PROJECTS=clang \
      -DLLVM_TARGETS_TO_BUILD="BPF" \
      -DCMAKE_INSTALL_PREFIX=${TARGET_DIR} \
      -G "Ninja" \
      -DCMAKE_BUILD_TYPE=Release \
      -DLLVM_BUILD_TOOLS=OFF \
      -DLLVM_ENABLE_TERMINFO=OFF \
      -DLLVM_INCLUDE_EXAMPLES=OFF \
      -DLLVM_INCLUDE_TESTS=OFF \
      -DLLVM_INCLUDE_BENCHMARKS=OFF \
      -DLLVM_STATIC_LINK_CXX_STDLIB=ON \
      -DLLVM_ENABLE_BINDINGS=OFF \
      -DLLVM_PARALLEL_COMPILE_JOBS=2 \
      -DLLVM_PARALLEL_LINK_JOBS=1 \
      ../llvm

cmake --build . --target install
cd ${TARGET_DIR}
rm -rf bin share libexec lib/clang lib/cmake lib/*.so*
