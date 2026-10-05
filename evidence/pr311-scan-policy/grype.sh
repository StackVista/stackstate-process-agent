set -euo pipefail

vex_args=()
while IFS= read -r doc; do
  if [ -n "${doc}" ]; then
    vex_args+=(--vex "${doc}")
  fi
done < reports/grype-vex-documents.txt

if [ "${#vex_args[@]}" -eq 0 ]; then
  echo "::error::No OpenVEX documents were prepared for Grype"
  exit 1
fi

skip_args=()
while IFS= read -r path; do
  path="${path#"${path%%[![:space:]]*}"}"
  path="${path%"${path##*[![:space:]]}"}"
  [ -z "${path}" ] && continue
  skip_args+=(--exclude "${path}")
done <<< "${INPUT_SKIP_FILES}"

echo "::group::Grype vuln report (table)"
grype "${INPUT_IMAGE}" "${vex_args[@]}" "${skip_args[@]}" --by-cve -o table -o "json=reports/grype.json"
echo "::endgroup::"
