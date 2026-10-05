set -euo pipefail

skip_args=()
while IFS= read -r path; do
  path="${path#"${path%%[![:space:]]*}"}"
  path="${path%"${path##*[![:space:]]}"}"
  [ -z "${path}" ] && continue
  skip_args+=(--skip-files "${path}")
done <<< "${INPUT_SKIP_FILES}"

for attempt in 1 2 3; do
  if trivy image \
    --scanners vuln \
    "${skip_args[@]}" \
    --format json \
    --output reports/trivy.json \
    --severity "${INPUT_SEVERITY}" \
    --vex repo \
    --skip-vex-repo-update \
    --exit-code 0 \
    "${INPUT_IMAGE}"; then
    break
  fi
  if [ "${attempt}" -eq 3 ]; then
    echo "::error::Trivy vulnerability scan failed after ${attempt} attempts"
    exit 1
  fi
  echo "::warning::Trivy vulnerability scan failed; retrying in 10s (attempt ${attempt}/3)"
  sleep 10
done
echo "::group::Trivy vuln report (table)"
trivy convert --format table reports/trivy.json
echo "::endgroup::"
