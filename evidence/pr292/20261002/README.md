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
