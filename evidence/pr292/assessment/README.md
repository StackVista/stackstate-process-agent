# PCRE2 / glibc assessment for PR292

Source candidate: [PR292](https://github.com/StackVista/stackstate-process-agent/pull/292), signed head `c86d936d5833e97b6e6daccb3d1e7beec3e3b2c1`. Its sole parent is retained PR290 head `fe7d17e97be17d62ac0ae1cf0760826cc6303f43`. Retained PR278 head `c4840469c675351ab1075f8a8469027828635e51` is an ancestor. Neither retained branch, evidence nor security policy changed.

## What is new

The delivered `af40af2b` image has the two newly active OS advisories. **PR290's already-published amd64 and arm64 images contain both fixed RPMs.** The JSON extraction here identifies the exact existing image digests, inventories and package versions from its [independently accepted evidence](https://github.com/StackVista/stackstate-process-agent/tree/786a1afae831eb5a714f5f744882b7a282f8dfb7/evidence/pr290/35322708539). No new PR290 build, scan or applicability review was performed.

PR292 adds two package minimum versions to the existing zypper install. This prevents a stale mirror from producing a runtime with older packages, even while the scanner operates in inform mode. PR292 is not required to remediate these two findings in the already-published PR290 images; it adds enforcement for subsequent builds.

| Package | Delivered version | Required minimum / already in PR290 |
| --- | --- | --- |
| libpcre2-8-0 | 10.42-150600.1.26 | 10.42-150600.3.3.1 |
| glibc | 2.38-150600.14.55.1 | 2.38-150600.14.58.1 |

These versions are confirmed by the official [PCRE2 SUSE-SU-2026:4241-1](https://www.suse.com/support/update/announcement/2026/suse-su-20264241-1/) and [glibc SUSE-SU-2026:4250-1](https://www.suse.com/support/update/announcement/2026/suse-su-20264250-1/) package lists for Basesystem 15 SP7, including x86_64 and aarch64 (retrieved 2026-09-19).

## Base choice and validation

BCI micro 15.7 with the existing BCI base 15.7 installroot builder already supplies the fixed versions. A different BCI flavor or release adds migration work without helping this fix, and no custom runtime code is needed. The new constraints follow the existing ACL/attr package requirements, permit future upgrades and leave the current runtime layout and package selection intact.

`zypper-floor-control.txt` records an amd64 control on `registry.suse.com/bci/bci-base:15.7`, resolved to `sha256:a1bff75c7ab3d66c8423e3f2370838d5dbed077a4133e9f38a98d7525a630958`. A refreshed repository accepts the two requirements. An intentionally unavailable PCRE2 requirement (`>=999`, dry run only) exits 104. This demonstrates rejection of an unsatisfiable floor; it does not substitute for native candidate image builds and scans.

The candidate's [normal CI run 35433121073](https://github.com/StackVista/stackstate-process-agent/actions/runs/35433121073) retains all required checks. See the subsequent published-image evidence directory for final validation; this assessment itself makes no clean-image claim.

## Verified current baseline

[Reporter run 35425413598, attempt 1](https://github.com/StackVista/cve-reporter/actions/runs/35425413598):

- `aggregate.zip` is the unchanged [artifact 10578198396](https://github.com/StackVista/cve-reporter/actions/runs/35425413598/artifacts/10578198396), SHA-256 `c0649a1c1eb0ebac5d1effd19bab4126d62636dad009777f96f4d10c118ce6fe`, matching the assigned scan.
- `baseline.zip` is the unchanged process-agent [artifact 10578499554](https://github.com/StackVista/cve-reporter/actions/runs/35425413598/artifacts/10578499554), SHA-256 `edefef8ad9d3d1eeeb39fde59442495c2b30adc65ba5fa4a397338baacdb1128`, matching GitHub artifact metadata.
- `baseline-verification.json` extracts the target metadata and two Trivy SUSE advisory rows. Grype does not report those two rows in that baseline; no dual-scanner positive detection is claimed.

Check this directory with `sha256sum -c SHA256SUMS`.

## Remaining decisions and delivery

Supervisor-routed independent review is required for the new source/evidence. [GO-2026-5932 human hold](https://github.com/StackVista/cve-reporter/issues/27), the expired exception, human merge/release decisions and complete later delivery evidence remain. No VEX/exception change, merge, production promotion or deployment is authorized by this assessment. Supervisor owns canonical ticket updates and review handoff.
