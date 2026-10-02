# PR #292 merged-image publication

Source: `00f55972777a43e1281461cb5696e9ec09bdef34`, the human-approved merge of PR #292 on October 2, 2026. Ordinary push CI: https://github.com/StackVista/stackstate-process-agent/actions/runs/36998783077. No release/tag action is required for its commit-image publication.

Delivered image: `quay.io/stackstate/stackstate-k8s-process-agent:00f55972`. Index: `sha256:a4919324549fe040eee1b66f83b885ed511ada6b2a6b7ec50cde01a172cc9d92`.

| Platform | Runtime digest |
| --- | --- |
| amd64 | `sha256:ab817bda6c5e53b65a5c804eb0c30cbe6b06b4ba771285f94eb89b5e91f7cff1` |
| arm64 | `sha256:b4f431ac216e0e111eab70937749b49d5a6ae05cad68ca87904e40316a0523a5` |

The merge-built candidate reports clear all six assigned Trivy rows, contain containerd v1.7.36 and all five GLib RPMs at 2.78.6-150600.4.41.1, and have zero secrets. Local candidate reports retain the existing UNKNOWN GO-2026-5932; each retains 79 Grype matches. Reports are byte-identical to the artifacts recorded in merge-artifacts.json.

The isolated workflow on this evidence branch reuses the previous dual-scanner publication check. It verifies the original signed master index, scans both published runtime digests on native architecture runners, compares packaged binaries byte-for-byte with merge-tested CI artifacts and records their source metadata, inventories and both scanners' output. It does not rebuild or publish images, add any VEX/ignore/suppression/exception, or change the required product CI gates. Publication verification https://github.com/StackVista/stackstate-process-agent/actions/runs/37000673264 passed on both architectures. Both published reports contain zero Trivy findings at all severities and zero secrets, while retaining 78 Grype matches per architecture (2 Critical, 24 High, 48 Medium, 4 Low). Each inventory contains 433 components and 125 RPMs. Original index signatures verify, source metadata matches the merge commit, and binaries match merge-tested artifacts byte-for-byte. Existing VEX configuration is reused without additions; the pre-existing local-candidate UNKNOWN does not appear in the published-image results.

The verified dev scan 36983036771/1 associates this image with suse-observability-agent 1.7.7. The consumer source is `stable/suse-observability-agent/values.yaml` in https://github.com/StackVista/helm-charts-internal. Its conventions select the eight-character published commit image tag. Chart adoption uses the repository bump script and generated helm-docs README.

Tracking: https://github.com/StackVista/cve-reporter/issues/69. Supervisor owns routine ticket updates; the intake remains open pending reviewed chart adoption and delivery. No chart merge, tag, release, production promotion or deployment is performed in this workstream.

## Consumer adoption

PR: https://github.com/StackVista/helm-charts-internal/pull/267
Signed source head: `0547ee4c4` (full identity in chart-adoption.json).
The three-file adoption updates nodeAgent.containers.processAgent.image.tag to `00f55972`, bumps agent chart 1.7.7 to 1.7.8 using scripts/bump-chart-version/bump_chart_version.py, and regenerates its README. The commit tag was independently checked with Skopeo to resolve to the verified delivered index.

Local Helm lint, default rendering, quoted-tag validation, local dependency/version-bump validation, all 12 registry image-reference checks and focused process-agent chart tests passed. The existing Skopeo validator rejects tag@digest references, so adoption follows the repository's supported commit-tag convention. Validators and CI gates remain unchanged. No new VEX, ignore rules, suppressions or exceptions were added.

Chart CI and human review/merge remain pending. No chart release/publication, Git tag, promotion or deployment was invoked. The canonical intake remains open.

To verify the evidence, run `sha256sum -c SHA256SUMS` here. Extract each published report ZIP separately and run its included SHA256SUMS check. published-verification.json records package/source/binary/image identities, raw Trivy results and retained Grype counts. publication-artifacts.json records byte-identical Actions archive digests. The workflow exists only on this evidence branch, outside the product and chart PR diffs.
