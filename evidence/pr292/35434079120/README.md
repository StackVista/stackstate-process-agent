# PR292 published-image validation

Candidate [PR292](https://github.com/StackVista/stackstate-process-agent/pull/292) remains at signed source **c86d936d5833e97b6e6daccb3d1e7beec3e3b2c1**, one commit directly on retained PR290 **fe7d17e97be17d62ac0ae1cf0760826cc6303f43**. Only the existing BCI package install changes: require `libpcre2-8-0>=10.42-150600.3.3.1` and `glibc>=2.38-150600.14.58.1`.

**Both published runtime images satisfy those requirements. Both scanners report only UNKNOWN GO-2026-5932; zero OS findings and zero secrets.** The unchanged expired exception and [human hold](https://github.com/StackVista/cve-reporter/issues/27) remain. This is candidate evidence awaiting supervisor-routed independent review, not merge or clean-delivery clearance.

## CI and immutable publication

[CI35433121073](https://github.com/StackVista/stackstate-process-agent/actions/runs/35433121073) passed all eight required jobs: native amd64/arm64 prebuild, generated-code verification, module verification, build/unit tests and OpenPGP absence checks, runtime build/smoke tests, Trivy/Grype and separate secrets scans, signed architecture publication and signed multi-architecture index. Required source CI was unchanged.

[Published-image run 35434079120](https://github.com/StackVista/stackstate-process-agent/actions/runs/35434079120) passed both native jobs. Signed orchestration commit **d74bbdd7** on the separate `evidence/pr292-published` branch verifies and scans the already-published images without rebuilding. It checks out the exact candidate source and exceptions. PR278, PR290 and their accepted evidence remain unchanged.

Image repository: `quay.io/stackstate/stackstate-k8s-process-agent`.

Signed index: **sha256:1a45e3280e97fa2e463349d54142b3ca9737d934998b1b1df0c0d93666606ae4** (branch tag `c86d936d`).

| Native platform | Exact runtime manifest scanned |
| --- | --- |
| amd64 | `sha256:e0eeb7d5196e8d1121313aa6e6145c957a6e91687b3a1c045f0a5649b6b5eb65` |
| arm64 | `sha256:ff8c855b04a56bf430adbb54de24f0274f5f51cb919cc2fa2ec8d92505172312` |

Cosign verifies the original index signature, certificate and transparency-log inclusion with issuer `https://token.actions.githubusercontent.com` and exact certificate identity `https://github.com/StackVista/stackstate-process-agent/.github/workflows/ci.yml@refs/pull/292/merge`. Each scanned runtime is a member of that index. Native architecture, exact revision label, binary build metadata and version output match the candidate.

`ci-binary-verification.json` records hashes of downloaded original CI artifacts. The actual published-image binaries match byte-for-byte:

- amd64: `1577959a1925498acfe62bf77e0f2344b1b0980ab021923ecbb9d2c6f9a166ed`
- arm64: `284d8d384a5bedd6e12247ecb2b5ce1d6c9f5a9ddc800a13194091378983ac0b`

## Scan results and comparison

Both full-image inventories contain **433 components / 125 RPM packages**. Both installed packages match the required fixed versions. `rpm-comparison.json` confirms that **all 125 RPM names and versions match PR290's accepted inventories**, not only PCRE2/glibc. The same BCI release remains sufficient and the enforcement adds no packages. PR290 already addresses these new OS findings in its published candidate; PR292 prevents future builds from selecting older versions. See the [assessment](../assessment/README.md) for the verified positive delivered-image scan and zypper rejection control.

The full-image Trivy and Grype reports identify the exact requested runtime digest and inspected image/config ID; the separate secrets report identifies the same image. Both inventories and binaries retain gRPC 1.83.2, containerd 1.7.35 and OTel SDK/trace exporters 1.45.0. CVE-2026-84445, CVE-2026-53495, CVE-2026-81870 and both targeted SUSE advisories are absent.

Trivy 0.70.0 database updated **2026-09-19 07:03:12 UTC**. Grype 0.112.0 database built **2026-09-19 06:27:50 UTC**, status valid. Versions and DB metadata are archived for both platforms. The original baseline positively detects the two SUSE advisories in Trivy; no Grype positive baseline claim is made.

Each evaluator reports **total 1 / suppressed 0 / expired 1 / unmanaged 0 / unused exceptions 0**. Each scanner's sole finding is GO-2026-5932 on x/crypto v0.56.0. `exceptions/GO-2026-5932.yaml` is byte-identical to source and remains expired on September 10.

The consumed approved containerd VEX remains byte-identical, SHA-256 **b30ad305d42a3ddbeeed6526ed2a7ceac96337a071bf044a305d8ee6b4d1f2ac**. Grype ignores exactly the expected three containerd 1.7.35 findings via `vex-status: not_affected`: CVE-2026-50195, CVE-2026-53489 and CVE-2026-53492. No new applicability decision or exception was made; accepted Go source/runtime controls were reused.

## Durable raw evidence and reproduction

The ZIP files are unmodified Actions artifact downloads, checked against the SHA-256 digests in `artifact-metadata.json`:

- [amd64 artifact 10581496916](https://github.com/StackVista/stackstate-process-agent/actions/runs/35434079120/artifacts/10581496916): `a7413fbeda39f608034f81b4168ba64756bcd4b39e4d467954d2dc7c13173443`
- [arm64 artifact 10581657606](https://github.com/StackVista/stackstate-process-agent/actions/runs/35434079120/artifacts/10581657606): `9af13e68302f92ca9ecf360bd006dc5204642bb0fb9cc832847939c1a9b0d078`

Actions retention is 90 days; these signed Git copies preserve reports independently of retention. Each archive includes original index/signature verification, image inspection, binary metadata/hash, full SBOM/RPM inventory, raw scanner and separate secrets reports, evaluator/SARIF, consumed VEX, unchanged exception, provenance and internal checksums.

From this directory in a clone containing the candidate source:

```sh
sha256sum -c SHA256SUMS
unzip -q amd64-reports.zip -d amd64
unzip -q arm64-reports.zip -d arm64
python3 verify-evidence.py
```

The verifier reuses the retained PR290 evidence verifier with the new source/digests and CI binary hashes, adds fixed-package and Trivy image-ID assertions, verifies internal report checksums, and reproduces `verification.json`.

## Unresolved work

Supervisor-routed independent source/publication review; human GO-2026-5932 disposition and merge approval; human-authorized release/promotion; later complete delivered/chart scan and independent delivery evidence for canonical issue69. PR292 is stacked on PR290, and both retained reviewed heads remain available. Green inform-mode CI and branch images do not grant merge or production clearance. No merge, deployment, VEX/exception approval, ticket update or whole-estate scan occurred in this workstream.
