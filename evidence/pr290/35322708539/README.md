# PR290 already-published runtime evidence

[Run 35322708539](https://github.com/StackVista/stackstate-process-agent/actions/runs/35322708539) completed successfully on 2026-09-18. Both native architecture jobs scanned the **existing published runtime manifests**. No source rebuild, image publication, promotion, deployment, VEX change or exception change occurred.

PR290 source remains **fe7d17e97be17d62ac0ae1cf0760826cc6303f43**. Signed orchestration commit **e8f264ac321dff9bc439662ae0598911aca67998** on `evidence/pr290-published` runs only inspection, signature checks and scans. PR278 remains c4840469c675351ab1075f8a8469027828635e51; no new application candidate head was needed.

## Signed index and exact runtime digests

Image repository: `quay.io/stackstate/stackstate-k8s-process-agent`.

Original published index: `sha256:6635bd08a5fa43b7f5668a838d9a59042f41eb0603264b465067192bd1b0a112` (branch tag `fe7d17e9`). Each job verifies the original index signature with issuer `https://token.actions.githubusercontent.com` and exact certificate identity `https://github.com/StackVista/stackstate-process-agent/.github/workflows/ci.yml@refs/pull/290/merge`, then asserts its native platform digest occurs in that signed index. Cosign verifies the signing certificate and transparency-log inclusion. Signature output and index JSON are in each report archive.

| Architecture | Runtime manifest scanned directly | Extracted binary SHA-256 |
| --- | --- | --- |
| amd64 | `sha256:271e7ac612adc3b89c10aa1bdbc463e4f62d7645c59f3938f27aa2c5500dcc8b` | `7ef8fb4948f69933c4d0666ac6d0a68a9164635e2405ddd044f700ca786d6b76` |
| arm64 | `sha256:c5deb88549c25db1f42568f7d6bed7f6b5ae1bac1b6785540e97425ef48135de` | `96b7397a7657873556c2216e3d2fb3daf2fb78f1b24e48e6e8892fd4d14a30d5` |

Image inspection confirms native architecture and the exact source revision label. Extracted binaries record `vcs.revision=fe7d17e97be17d62ac0ae1cf0760826cc6303f43`, `vcs.modified=false`, and match the original PR290 CI binary hashes. Both binary metadata and full-image SBOM identify OTel SDK/trace exporters **v1.45.0**, gRPC **v1.83.2**, and containerd **v1.7.35**. Version smoke tests pass.

Scanners use those exact immutable runtime inputs. Grype's Docker-source `manifestDigest` is its Docker representation, not the registry OCI runtime digest; its `userInput`/`repoDigests` identify the requested OCI manifest and its image ID equals Docker inspection. The verification script checks this identity rather than conflating these digest types.

## Current published-image results

Both Trivy and Grype report exactly **one UNKNOWN GO-2026-5932** on x/crypto v0.56.0. No CVE-2026-81870, CVE-2026-84445 or CVE-2026-53495 remains. No OS findings. Each separate whole-image secrets scan reports **zero findings**.

Each evaluator reports **total 1, suppressed 0, expired 1, unmanaged 0, unused exceptions 0**. The exact source exception expired 2026-09-10 and is unchanged. **GO-2026-5932 remains a human hold**; green `inform` mode is not clean-image or merge clearance.

Each full-image CycloneDX SBOM inventories **433 components, including 125 RPM packages**. RPM inventories are derived from the complete SBOM using the previously validated PR278 recovery method.

Grype `ignoredMatches` contains exactly containerd **v1.7.35** CVE-2026-50195, CVE-2026-53489 and CVE-2026-53492, each with `namespace: vex` and `vex-status: not_affected`. Both jobs retain the normal scan action's consumed StackVista containerd VEX document, SHA-256 **b30ad305d42a3ddbeeed6526ed2a7ceac96337a071bf044a305d8ee6b4d1f2ac**, byte-identical to the approved document already verified by independent review. No applicability/module controls were repeated. Trivy retains no containerd findings.

The normal scan action is pinned to `6284a6fc006a7cc46a7f00d02c50d5f21b117b63`: Trivy 0.70.0 and Grype 0.112.0. Grype's valid database was built **2026-09-18T06:30:15Z**, the same database date as the recovered PR278 scans that positively report OTel81870. Existing OTel runtime regression evidence (old version leaks, fixed version does not) and source/build tests remain on PR290 and were reused.

## Durable reports

Actions copies retained for 90 days: [amd64](https://github.com/StackVista/stackstate-process-agent/actions/runs/35322708539/artifacts/10537733296), [arm64](https://github.com/StackVista/stackstate-process-agent/actions/runs/35322708539/artifacts/10537204046).

The compressed archives preserve those complete report artifacts in signed Git history, independent of Actions retention: image inspection, original index signature/index membership, binary metadata/hash, full inventory, raw dual-scanner and separate secrets reports, evaluator/SARIF, unchanged exception, consumed VEX and provenance. `verification.json` records the independently checked assertions over the downloaded reports. No old pre-publication reports are duplicated here.

From this directory in a clone containing the PR source:

```sh
sha256sum -c SHA256SUMS
tar -xzf amd64-reports.tar.gz
tar -xzf arm64-reports.tar.gz
python3 verify-evidence.py
```

The verifier checks internal report checksums, exact source/image/scanner/binary identities, published-index membership, original index signature digest, module versions in binaries and inventories, VEX bytes and suppressions, target CVE absence, residual finding/expired-exception state and separate secrets.

This closes the specific pre-publication versus published-runtime evidence gap for PR290. Supervisor-routed independent review, GO-2026-5932 human disposition, human merge approval and later production/chart delivery evidence remain outstanding.
