set -euo pipefail
for report in reports/trivy-secrets.json reports/trivy.json; do
  jq -e '
    .SchemaVersion == 2 and
    (.ArtifactName | type == "string" and length > 0) and
    (.Results == null or (.Results | type == "array"))
  ' "${report}" > /dev/null
done
jq -e 'type == "object" and (.matches | type == "array")' reports/grype.json > /dev/null
jq -e '.version == "2.1.0" and (.runs | type == "array" and length > 0)' reports/image-pipeline.sarif > /dev/null
