# Process-agent chart delivery after PR #267

The requested closure evidence is complete for the six assigned Trivy-only process-agent rows in the dev/internal chart delivery. Human merge, normal chart publication, packaged image selection, per-architecture digest resolution, fresh no-VEX vulnerability scans and separate all-severity secret scans are verified. The ticket remains open for the supervisor; no ticket or Project update was performed.

Raw all-severity Trivy is **not zero-finding**: both architectures still report the pre-existing UNKNOWN `GO-2026-5932` on `golang.org/x/crypto v0.56.0`, outside the six assigned rows. No VEX was applied. Grype findings remain disclosed without remediation or new suppressions. This evidence does not claim public/Rancher promotion, cluster deployment, or a whole-estate scan.

## Human merge and normal publication

- Adoption: [helm-charts-internal #267](https://github.com/StackVista/helm-charts-internal/pull/267), human-merged October 2, 2026 at 13:08:34 UTC as `8acf7a1596c1e84a2e521a32618e9d95ef609da7`. Repository default branch is `master`.
- [Merge CI 37011044156](https://github.com/StackVista/helm-charts-internal/actions/runs/37011044156) succeeded. Its [normal internal publication job](https://github.com/StackVista/helm-charts-internal/actions/runs/37011044156/job/110851892262) pushed and verified **suse-observability-agent 1.7.8** at 13:13:54 UTC.
- [Public source synchronization 37011044212](https://github.com/StackVista/helm-charts-internal/actions/runs/37011044212) succeeded. It synchronizes source; it does not publish a public chart. No 1.7.8 public chart package appeared in the checked public index. Public/Rancher chart release remains a separate human-operated workflow, not invoked here.
- Published package: <https://helm-internal.stackstate.io/charts/suse-observability-agent-1.7.8.tgz>. The downloaded archive SHA256 is `ecb82ccddfdba66608bf48888fa6b070c3cee6843e623089d346e56a6e7c04b1`, matching the internal repository index entry created at `2026-10-02T13:13:54.090988582Z`.
- Published package values match the merged source byte-for-byte. Rendering the actual published archive selects `quay.io/stackstate/stackstate-k8s-process-agent:00f55972` for the process-agent DaemonSet container. This is the chart that the assigned dev scan consumes.

## Exact chart-selected image

Index digest: `sha256:a4919324549fe040eee1b66f83b885ed511ada6b2a6b7ec50cde01a172cc9d92`.

| Architecture | Exact runtime digest scanned |
| --- | --- |
| amd64 | `sha256:ab817bda6c5e53b65a5c804eb0c30cbe6b06b4ba771285f94eb89b5e91f7cff1` |
| arm64 | `sha256:b4f431ac216e0e111eab70937749b49d5a6ae05cad68ca87904e40316a0523a5` |

The downloaded raw OCI index and platform manifest hashes match these identities. All scanner reports record these exact runtime/config identities and architecture; image revision labels match process-agent source `00f55972777a43e1281461cb5696e9ec09bdef34`. Existing [merge-triggered image publication CI](https://github.com/StackVista/stackstate-process-agent/actions/runs/36998783077) and [published-image/binary verification](https://github.com/StackVista/stackstate-process-agent/actions/runs/37000673264) remain supporting evidence. This fresh delivery check adds scans without VEX and ties those images to the published consuming chart.

## Fresh delivery scan results

Both architectures:

- `CVE-2026-53493` absent; the linked `github.com/containerd/containerd` module is **v1.7.36**.
- `SUSE-SU-2026:4367-1` absent for all five assigned RPMs: `glib2-tools`, `libgio-2_0-0`, `libglib-2_0-0`, `libgmodule-2_0-0`, and `libgobject-2_0-0`. Each is **2.78.6-150600.4.41.1**.
- Separate secret scan: **zero secrets**, with severity `UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL`.
- Remaining raw Trivy: one UNKNOWN `GO-2026-5932`; no HIGH/MEDIUM/LOW/CRITICAL findings. No VEX or local ignores were applied.
- Raw Grype: **78 matches per architecture** (2 Critical, 24 High, 48 Medium, 4 Low), zero ignored matches. They are retained for disclosure only.

Trivy 0.74.0 used its database updated October 2 at 12:48 UTC. Grype 0.117.0 used the valid v6.1.9 database built October 2 at 06:31:53 UTC. Scanner-specific environment overrides were absent and cleared for the scan commands. An empty one-off scanner config was used, Trivy `--vex ''` explicitly selected no VEX, and `--ignorefile /dev/null` applied no ignores. Grype reports confirm no VEX documents and zero ignored matches. No unfixed or severity filtering hid vulnerabilities: all severities were requested.

`assigned-findings.json` retains the six exact finding keys from [dev scan 36983036771, attempt 1](https://github.com/StackVista/cve-reporter/actions/runs/36983036771). Its original aggregate was downloaded and verified against `sha256:600d791947fc21560ab206d820e80af13dab87d0de836377c73cda6046e96345` before filtering exactly `owner_repo == "stackstate-process-agent"` and `scanners == ["Trivy"]`. `delivery-verification.json` maps every assigned row to the installed fixed version and absence in both fresh reports.

## Evidence verification

Run `sha256sum -c SHA256SUMS` in this directory, extract both report ZIPs here, and download the immutable-version published chart archive from the URL above as `suse-observability-agent-1.7.8.tgz`. Then run `python3 verify-delivery.py`. It verifies chart archive hash, index and platform hashes, scanner/config/source identity, no-VEX commands, complete coverage of the six assigned rows, installed fixed versions, and the separate secret scan results.

`scan-command-receipts.json` retains exact commands, UTC start/end times and successful exit statuses. Each architecture ZIP contains complete unmodified Trivy vulnerabilities, separate secrets and Grype reports plus scan logs. The repository index entry, actual archive selection, merge/publication receipts, scanner versions and database metadata are retained beside them. One-off outputs exist only on this evidence branch, outside product/chart diffs.

No manual release, retag, republish, new CVE workflow run, gate/VEX/ignore/exception change, or infrastructure change occurred. No source or branch owned by PR #268 or #270 was touched. Publication did not fail; there is no blocker for the assigned internal/dev delivery evidence.

Canonical intake: <https://github.com/StackVista/cve-reporter/issues/69>. Supervisor owns its closure decision. If “Trivy-clean” is intended to include the separate UNKNOWN finding, this raw scan does not establish that broader zero-finding claim.
