# PR #292 merged-image publication

Source: `00f55972777a43e1281461cb5696e9ec09bdef34`, the human-approved merge of PR #292 on October 2, 2026. Ordinary push CI: https://github.com/StackVista/stackstate-process-agent/actions/runs/36998783077. No release/tag action is required for its commit-image publication.

Delivered image: `quay.io/stackstate/stackstate-k8s-process-agent:00f55972`. Index: `sha256:a4919324549fe040eee1b66f83b885ed511ada6b2a6b7ec50cde01a172cc9d92`.

| Platform | Runtime digest |
| --- | --- |
| amd64 | `sha256:ab817bda6c5e53b65a5c804eb0c30cbe6b06b4ba771285f94eb89b5e91f7cff1` |
| arm64 | `sha256:b4f431ac216e0e111eab70937749b49d5a6ae05cad68ca87904e40316a0523a5` |

The merge-built candidate reports clear all six assigned Trivy rows, contain containerd v1.7.36 and all five GLib RPMs at 2.78.6-150600.4.41.1, and have zero secrets. Local candidate reports retain the existing UNKNOWN GO-2026-5932; each retains 79 Grype matches. Reports are byte-identical to the artifacts recorded in merge-artifacts.json.

The isolated workflow on this evidence branch reuses the previous dual-scanner publication check. It verifies the original signed master index, scans both published runtime digests on native architecture runners, compares packaged binaries byte-for-byte with merge-tested CI artifacts and records their source metadata, inventories and both scanners' output. It does not rebuild or publish images, add any VEX/ignore/suppression/exception, or change the required product CI gates. Publication verification is pending at this checkpoint.

The verified dev scan 36983036771/1 associates this image with suse-observability-agent 1.7.7. The consumer source is `stable/suse-observability-agent/values.yaml` in https://github.com/StackVista/helm-charts-internal. Its conventions select the eight-character published commit image tag. Chart adoption uses the repository bump script and generated helm-docs README.

Tracking: https://github.com/StackVista/cve-reporter/issues/69. Supervisor owns routine ticket updates; the intake remains open pending reviewed chart adoption and delivery. No chart merge, tag, release, production promotion or deployment is performed in this workstream.
