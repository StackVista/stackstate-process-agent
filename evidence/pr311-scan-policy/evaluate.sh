args=(
  --image "${INPUT_IMAGE}"
  --severity "${INPUT_SEVERITY}"
  --mode "${INPUT_MODE}"
  --trivy-json reports/trivy.json
  --sarif "${SARIF_PATH}"
)
if [ -n "${INPUT_EXCEPTIONS_PATH}" ]; then
  if [ ! -d "${INPUT_EXCEPTIONS_PATH}" ]; then
    echo "::error::exceptions-path '${INPUT_EXCEPTIONS_PATH}' does not exist or is not a directory"
    exit 1
  fi
  args+=(--exceptions "${INPUT_EXCEPTIONS_PATH}")
  echo "::notice::Using exceptions from '${INPUT_EXCEPTIONS_PATH}'"
else
  echo "::notice::No exceptions-path provided; evaluating without local exceptions"
fi
if [ -f reports/grype.json ]; then
  args+=(--grype-json reports/grype.json)
fi
set +e
image-pipeline-evaluate "${args[@]}"
code=$?
set -e
echo "sarif-path=${SARIF_PATH}" >> "$GITHUB_OUTPUT"
echo "exit-code=$code" >> "$GITHUB_OUTPUT"
if [ "$code" -eq 0 ]; then
  echo "decision=passed" >> "$GITHUB_OUTPUT"
else
  echo "decision=failed" >> "$GITHUB_OUTPUT"
fi
