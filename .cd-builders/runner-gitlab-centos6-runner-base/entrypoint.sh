#!/bin/bash -l
set -e

source /root/.bashrc

if command -v conda; then
  # Only try to use conda if it's installed.
  # On ARM images, we use the system Python 3 because conda is not supported.
  conda activate processagentpy3
fi

exec "$@"
