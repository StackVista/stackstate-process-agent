# PR #292 Trivy remediation validation

Candidate: `a0a3d2fb0a224fcf0e93de1aec3295fde7913e3a` on `cve-pcre2-glibc-runtime`.

This separate evidence branch carries a one-off workflow that checks the published candidate images; it is outside the product PR diff. It reuses the prior PR #292 publication-verification workflow and the pinned image-pipeline scan action. It does not build or publish images, change VEX or exceptions, or deploy anything.

The workflow pins the source, candidate CI run, signed OCI index and both runtime digests. Native runners compare the extracted published binaries byte-for-byte with the tested CI artifacts, check source/version metadata, retain full RPM inventories, and assert that the six assigned Trivy rows and secrets are absent. This evidence run uses Trivy only; all original required product CI checks, including Grype in inform mode, remain intact on the candidate.

Baseline: https://github.com/StackVista/cve-reporter/actions/runs/36983036771 (attempt 1).
Verified aggregate: `sha256:600d791947fc21560ab206d820e80af13dab87d0de836377c73cda6046e96345`.
Verified per-image archive: `sha256:9cf5284394a679923f1a5f28c935c1d9353af5f5d4c33f0b3143196da1e2cbec` (artifact 11215918659).

Six assigned rows: `CVE-2026-53493` on containerd v1.7.35 and `SUSE-SU-2026:4367-1` on glib2-tools/libgio/libglib/libgmodule/libgobject 2.78.6-150600.4.38.1. The aggregate filter is exactly `scanners == ["Trivy"]`. Grype-only findings are outside the assigned remediation scope.

Independent local checks: go mod verify passed; upstream 1.7.35/1.7.36 go.mod files are byte-identical; containerd v1.7.36's upstream TestWalk*/TestDispatch* tests passed; BCI 15.7 zypper resolves all five GLib minimum requirements. A fresh Trivy 0.74.0 baseline scan also detects all six target rows, plus raw UNKNOWN GO-2026-5932 before applying approved VEX.

Product CI: https://github.com/StackVista/stackstate-process-agent/actions/runs/36991914873.
PR: https://github.com/StackVista/stackstate-process-agent/pull/292.
Tracking: https://github.com/StackVista/cve-reporter/issues/69 and https://github.com/StackVista/stackstate-process-agent/issues/260.

Human merge/release decisions and later chart adoption/delivery validation remain separate. The supervisor owns ticket/Project updates. Previous signed source/evidence checkpoints are preserved.

## Final publication result

[Publication CI 36994022044](https://github.com/StackVista/stackstate-process-agent/actions/runs/36994022044) passed on native amd64 and arm64. The signed index is `sha256:ea384c3380fc56d809133e1b26680f29488137a58e9abab4efd1155be7464a0c`. Runtime digests are `sha256:fb6e9f8546674f06a165c7668d45b6d57b9bd62b4edeafd29934da081bcb76fd` (amd64) and `sha256:9dc61c6e59fe8f97dc69b377fa74416920a7fd6623e1374de4917543450b1296` (arm64).

Each published binary matches its tested CI artifact byte-for-byte and reports source revision a0a3d2fb with vcs.modified=false. Each complete inventory has 433 components and 125 RPMs. Containerd is v1.7.36; all five targeted GLib RPMs are 2.78.6-150600.4.41.1. Both published reports contain zero Trivy vulnerabilities at all severities after applying the existing approved VEX, and zero secrets. No VEX or exception was changed.

Locally built candidate reports retain the known UNKNOWN GO-2026-5932 and the unchanged September 10-expired bridge exception. Actual published-image reports clear that finding through the existing VEX path; the maintained OpenPGP-absence source control passed in both native build jobs. Grype-only reports are outside remediation scope, and original required CI continues to run Grype in inform mode. Workflow success alone is not merge authorization.

The published report ZIPs are byte-identical to artifacts 11221062070 (amd64, sha256:c94d3fb15f57cd46114424c1055f896116ec5a092af789870c7f84bbc4b41e6d) and 11221255072 (arm64, sha256:240a230e4373ff4e3621a8e5ce66d1c248c25ee4f0cca1584b8bb9ba549ed6f0). All internal report SHA256SUMS checks pass. `published-verification.json` records the image/config/binary identities, versions and remaining findings. `candidate-artifacts.json` records the tested binary artifact identities.

To check this bundle, run `sha256sum -c SHA256SUMS` in this directory. Extract each published report archive into its own directory and run `sha256sum -c SHA256SUMS` there to verify its contents.

Outstanding: independent review of the new source/publication checkpoint, human merge/release/promotion approval, and later chart adoption/delivery verification. Supervisor retains ticket/Project ownership.
