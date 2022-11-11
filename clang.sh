#!/usr/bin/env bash

set -ex

EMBEDDED_PATH=/opt/stackstate/embedded

mkdir clangbuild
cd clangbuild

wget https://github.com/llvm/llvm-project/releases/download/llvmorg-11.0.1/clang-11.0.1.src.tar.xz -O clang.src.tar.xz
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-11.0.1/llvm-11.0.1.src.tar.xz -O llvm.src.tar.xz
mkdir clang && tar xf clang.src.tar.xz --strip-components=1 --no-same-owner -C clang
mkdir llvm && tar xf llvm.src.tar.xz --strip-components=1 --no-same-owner -C llvm

mkdir build
cd build

cmake -DLLVM_ENABLE_PROJECTS=clang \
      -DLLVM_TARGETS_TO_BUILD="BPF" \
      -DCMAKE_INSTALL_PREFIX=${EMBEDDED_PATH} \
      -G "Ninja" \
      -DCMAKE_BUILD_TYPE=MinSizeRel \
      -DLLVM_BUILD_TOOLS=OFF \
      -DLLVM_ENABLE_TERMINFO=OFF \
      -DLLVM_INCLUDE_EXAMPLES=OFF \
      -DLLVM_INCLUDE_TESTS=OFF \
      -DLLVM_INCLUDE_BENCHMARKS=OFF \
      -DLLVM_STATIC_LINK_CXX_STDLIB=ON \
      -DLLVM_ENABLE_BINDINGS=OFF \
      -DLLVM_PARALLEL_COMPILE_JOBS=4 \
      -DLLVM_PARALLEL_LINK_JOBS=4 \
      ../llvm

cmake --build . --target install
cd ${EMBEDDED_PATH}

rm -rf bin share libexec lib/clang lib/cmake lib/*.so*
#mkdir -p $CI_PROJECT_DIR/.tmp
#tar cvaf $CI_PROJECT_DIR/.tmp/clang-$ARCH-11.0.1.tar.xz .
#$S3_CP_CMD $CI_PROJECT_DIR/.tmp/clang-$ARCH-11.0.1.tar.xz $S3_PERMANENT_ARTIFACTS_URI/clang-$ARCH-11.0.1.tar.xz



#    1  cd /agent
#    2  pip3 install invoke
#    3  inv -e system-probe.object-files
#    4  yum install which clanhg
#    5  yum install which clang
#    6  inv -e system-probe.object-files
#    7  yum install clang=11
#    8  yum install clang
#    9  yum install clang-11
#   10  yum search clang
#   11  yum --showduplicates list clang
#   12  yum update
#   13  uname -a
#   14  cat /etc/centos-release
#   15  yum install llvm
#   16  yum --showduplicates list clang
#   17  yum --showduplicates list llvm
#   18  sudo yum install centos-release-scl
#   19  yum install centos-release-scl
#   20  yum install llvm-toolset-7
#   21  scl enable llvm-toolset-7 bash
#   22  history
