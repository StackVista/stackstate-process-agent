#!/usr/bin/env bash
# GO-2026-5932 is suppressed on the claim that openpgp is not linked. The
# scanners match the x/crypto module, not the package, so a change that starts
# importing openpgp would stay suppressed and otherwise reach a release unseen.
set -euo pipefail

packages="$(go list -deps ./cmd/...)"

if [ -z "${packages}" ]; then
  echo "go list -deps ./cmd/... resolved no packages" >&2
  exit 1
fi

if printf '%s\n' "${packages}" | grep -E '^golang\.org/x/crypto/openpgp(/|$)' >&2; then
  echo "golang.org/x/crypto/openpgp is reachable from ./cmd/..." >&2
  echo "Withdraw the GO-2026-5932 suppression and address the advisory, or drop the import." >&2
  exit 1
fi

printf 'openpgp absent from %s packages reachable from ./cmd/...\n' \
  "$(printf '%s\n' "${packages}" | wc -l)"
