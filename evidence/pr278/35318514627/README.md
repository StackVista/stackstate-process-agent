# PR278 exact-source published-image evidence

[CI35318514627](https://github.com/StackVista/stackstate-process-agent/actions/runs/35318514627) passed all ten jobs on 2026-09-18. This is candidate evidence, not merge clearance or production delivery evidence.

Source remains **c4840469c675351ab1075f8a8469027828635e51**, the unchanged reviewed [PR278](https://github.com/StackVista/stackstate-process-agent/pull/278). The candidate-only workflow ran at signed orchestration commit **9bbed017450fff18f1f4de7ec232742a21490d5f**. All build and image checkouts were pinned to the reviewed source, including the original Dockerfile and exception file. No new application candidate head was needed. PR290 remains separate at fe7d17e97be17d62ac0ae1cf0760826cc6303f43.

## Published images and signatures

Candidate tag: `quay.io/stackstate/stackstate-k8s-process-agent:c4840469-evidence-35318514627`.

Signed multi-architecture index: `sha256:68cfa5c411b96d7620c577a5ebc8f4975d277c7fd787db67e93347cb66fe541f`.

| Platform | Signed architecture index actually scanned | Platform image manifest |
| --- | --- | --- |
| amd64 | `sha256:5054522d33aff34692393328edaf992417f46d76644cd26e14bf51b0d4fa2a17` | `sha256:77a4944ae82361b8126ed27ce24290881958672a5289e7fdbf23a9dc0133a14a` |
| arm64 | `sha256:27a2367de7e8f46d050a3026481f36c83bf0777d67ecaf93e92cf7918369c426` | `sha256:3bcccb4a577775864f93c0086087ab404c89080dbcc3455011639cd44e0e08af` |

Each architecture index contains its platform image and an attestation manifest. The platform manifest matches the corresponding entry in the multi-architecture index. Native architecture jobs pulled and inspected these exact digests before scanning. Their image revision labels and extracted binaries record c4840469; binary build metadata records `vcs.modified=false`.

All three index signatures were verified locally with Cosign 3.1.3, including transparency-log and certificate validation, against issuer `https://token.actions.githubusercontent.com` and exact identity `https://github.com/StackVista/stackstate-process-agent/.github/workflows/ci.yml@refs/heads/evidence/pr278-full-image`. Verification output and index JSON are retained beside the reports. Verification can be repeated with:

```sh
cosign verify \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity=https://github.com/StackVista/stackstate-process-agent/.github/workflows/ci.yml@refs/heads/evidence/pr278-full-image \
  quay.io/stackstate/stackstate-k8s-process-agent@sha256:68cfa5c411b96d7620c577a5ebc8f4975d277c7fd787db67e93347cb66fe541f
```

## Published full-image results, both architectures

- Trivy and Grype: CVE-2026-84445 and CVE-2026-53495 absent. No OS findings.
- Both scanners retain three LOW CVE-2026-81870 rows: OTel SDK, otlptrace and otlptracegrpc v1.44.0. Separate PR290 addresses these.
- Both scanners retain UNKNOWN GO-2026-5932 on x/crypto v0.56.0. **Human hold remains.** The exact original exception file expired 2026-09-10; it is not renewed or removed.
- Each evaluator: total 4, suppressed by exception 0, expired 1, unmanaged 3, unused exceptions 0. `inform` mode returns success; this is not a clean-image verdict.
- Separate whole-image secret scans: zero findings, both architectures.
- Grype moves exactly CVE-2026-50195, CVE-2026-53489 and CVE-2026-53492 at containerd v1.7.35 to `ignoredMatches`, each `namespace: vex`, `vex-status: not_affected`. Trivy retains no containerd findings.
- The containerd VEX bytes downloaded through the normal scan action have SHA-256 **b30ad305d42a3ddbeeed6526ed2a7ceac96337a071bf044a305d8ee6b4d1f2ac**, matching the independent review of approved vexhub#42. No VEX/applicability investigation or edit was repeated.
- Each full-image CycloneDX inventory contains 433 components, including 125 RPM packages. RPM inventories are derived from the SBOM because the minimal runtime has no `rpm` executable.

Grype 0.112.0 used the database built 2026-09-18T06:30:15Z. Trivy is pinned to 0.70.0 in the unchanged scan action. These are scans of the **published images**, not merely the pre-publication build. Local-image reports are also retained in CI.

Binary SHA-256: amd64 `436fba8192a1b5be6caa885dcfaaf2d09ad98d26b2dfa16a47e48dfb7c226d95`; arm64 `96dec5fba9789f2c1db0614fe73953a8326ba32e30993074c78446788881ecfd`.

## Evidence access and validation

Actions copies, retained 90 days: [amd64 published reports](https://github.com/StackVista/stackstate-process-agent/actions/runs/35318514627/artifacts/10536683276), [arm64 published reports](https://github.com/StackVista/stackstate-process-agent/actions/runs/35318514627/artifacts/10536786552). Rebuilt binary/eBPF inputs: [amd64](https://github.com/StackVista/stackstate-process-agent/actions/runs/35318514627/artifacts/10536667331), [arm64](https://github.com/StackVista/stackstate-process-agent/actions/runs/35318514627/artifacts/10536506870).

The two report archives preserve the original artifact contents in signed Git history, independently of Actions retention. Each contains image inspection/digest, binary build information/hash, full-image SBOM, RPM inventory, raw dual-scanner JSON, separate secrets JSON, evaluator output/SARIF, the unchanged expired exception, consumed containerd VEX, provenance and checksums. `verification.json` summarizes the assertions run against both downloaded artifacts. To verify from this directory in a clone of the repository:

```sh
sha256sum -c SHA256SUMS
tar -xzf amd64-reports.tar.gz
tar -xzf arm64-reports.tar.gz
(cd amd64 && sha256sum -c SHA256SUMS)
(cd arm64 && sha256sum -c SHA256SUMS)
python3 verify-evidence.py
```

Independent review and human merge decisions remain outstanding. No production publication, deployment, VEX decision, ticket closure, or merge occurred.
