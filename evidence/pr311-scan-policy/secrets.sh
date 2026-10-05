set -euo pipefail

mkdir -p reports
for attempt in 1 2 3; do
  if trivy image \
    --scanners secret \
    --format json \
    --output reports/trivy-secrets.json \
    --exit-code 0 \
    "${INPUT_IMAGE}"; then
    break
  fi
  if [ "${attempt}" -eq 3 ]; then
    echo "::error::Trivy secrets scan failed after ${attempt} attempts"
    exit 1
  fi
  echo "::warning::Trivy secrets scan failed; retrying in 10s (attempt ${attempt}/3)"
  sleep 10
done
found=$(jq '[.Results[]?.Secrets // [] | .[]] | length' reports/trivy-secrets.json)
if [ "$found" -gt 0 ]; then
  echo "::error::Trivy detected $found secret(s) in image - failing scan (no exception path for secrets)"
  jq '.Results[]?.Secrets // []' reports/trivy-secrets.json
  exit 1
fi
echo "No secrets detected in image."
