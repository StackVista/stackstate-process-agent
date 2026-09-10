#!/usr/bin/env bash

# This script is used by prebuild-datadog-agent and CI to generate the prebuild files from a docker container

set -ex

# This command assumes the datadog agent to be mounted at /source-datadog-agent. To avoid outputting to that directory,
# we make a clone before running any commands
if [ -L "$WORKDIR" ] && [ -d "$WORKDIR" ]
then
  echo "$WORKDIR is a symlink to a directory. It is your responsibility to ensure that the directory has the up-to-date code."
else

  # coreutils cp, not rsync: the prebuild images are Debian bullseye, which is
  # EOL, so apt-get update exits 100 on the expired bullseye-security Release
  # file and installing rsync is no longer possible. cp -au needs no network.
  mkdir -p $WORKDIR

  # WORKDIR is reused across dependency versions while SOURCEDIR is
  # version-scoped, so a path can change type between runs. cp then either fails
  # outright (it cannot overwrite a non-directory with a directory) or, when -u
  # finds the destination no older, silently keeps the wrong type. rsync
  # replaced the destination in both cases, so unlink it first.
  #
  # Only non-directories are ever unlinked, using rm -f so that a directory
  # would fail rather than be removed: paths absent from SOURCEDIR must survive
  # to keep cp -au's non-delete behaviour, which the generated ebpf artifacts
  # rely on.
  #
  # xtrace off for the loop: it runs once per path in the dependency, which is
  # about 14 trace lines each and would bury the rest of the build log.
  set +x
  ( cd "$SOURCEDIR" && find . -mindepth 1 -print0 ) |
    while IFS= read -r -d '' rel; do
      rel=${rel#./}
      src="$SOURCEDIR/$rel"
      dst="$WORKDIR/$rel"

      if [ -L "$dst" ]; then dst_type=l
      elif [ -d "$dst" ]; then dst_type=d
      elif [ -e "$dst" ]; then dst_type=f
      else continue
      fi

      if [ -L "$src" ]; then src_type=l
      elif [ -d "$src" ]; then src_type=d
      else src_type=f
      fi

      if [ "$src_type" = "$dst_type" ]; then
        continue
      fi

      if [ "$dst_type" = d ]; then
        # rsync refused this too, rather than deleting a directory that may hold
        # generated output. Stop instead of building against a stale tree.
        echo "$rel is a directory in $WORKDIR but not in $SOURCEDIR: delete $WORKDIR and re-run" >&2
        exit 1
      fi

      rm -f "$dst"
    done
  set -x

  cp -au "$SOURCEDIR"/. $WORKDIR
  chown -R root:root $WORKDIR
fi

cd $WORKDIR

# Adding a faux tag to make the build pass on the rpo with no tags
git config user.email "you@example.com"
git config user.name "Your Name"
git tag -a 7.0.0 -m 7.0.0 || true

# This command will create system-probe. Running the go:generate as well as invoking the precompilation of the ebpf files
invoke system-probe.build

# If empty we try the fallback to the architecture of the host
if [ -z "$LLVM_ARCH" ]; then
    arch=$(uname -m)
    if [ "$arch" = "x86_64" ]; then
        LLVM_ARCH="x86_64"
    elif [ "$arch" = "aarch64" ] || [ "$arch" = "arm64" ]; then
        LLVM_ARCH="arm64"
    else
        echo "Unknown architecture: $arch"
        exit 1
    fi
fi

# todo!: These 2 outputs are only for debugging and we don't use them actually so at a certain point we could also remove them...
llvm-objdump -S $WORKDIR/pkg/ebpf/bytecode/build/${LLVM_ARCH}/usm-debug.o > $OUTPUTDIR/usm_debug.txt
llvm-objdump -S $WORKDIR/pkg/ebpf/bytecode/build/${LLVM_ARCH}/usm.o > $OUTPUTDIR/usm.txt

# Output the generated gofiles (including relative paths) to the output directory
# These go files contain the path to the ebpf source code that will be compiled at runtime. We don't use the runtime mode, so at a certain point we could avoid to build it.
mkdir -p "$OUTPUTDIR/gofiles"
git ls-files --others --ignored --exclude-from=pkg/ebpf/bytecode/runtime/.gitignore | grep "\.go$" | xargs -I{} cp --parents {} "$OUTPUTDIR/gofiles"
chown -R "$OUTPUT_USER_ID:$OUTPUT_GROUP_ID" "$OUTPUTDIR/gofiles"

# Output the ebpf files to the output directory
# We need the `.o` files that the process-agent will use at runtime. We only run in prebuilt mode so the .o files are enough
mkdir -p "$OUTPUTDIR/ebpf/"
cp -r ./pkg/ebpf/bytecode/build/* "$OUTPUTDIR/ebpf/"
chown -R "$OUTPUT_USER_ID:$OUTPUT_GROUP_ID" "$OUTPUTDIR/ebpf"
