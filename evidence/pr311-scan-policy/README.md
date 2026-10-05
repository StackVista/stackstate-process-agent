# Process-agent reporting-only policy validation

Product PR: https://github.com/StackVista/stackstate-process-agent/pull/311
Exact signed head: `4bc4594d6a2ee6cb5c13a65d87e1c3f10f77f789` (GitHub verification `valid`, local SSH signature `G`).
Default-branch base: `00f55972777a43e1281461cb5696e9ec09bdef34`.
Policy intake: https://github.com/StackVista/stackstate-process-agent/issues/310, in Project 4 before PR creation.

The base already uses `scan-image` mode `inform`. The one-file product follow-up keeps that mode, both scanners, all vulnerability severities and the original pinned action. It explicitly sets all secret severities, rejects missing/invalid required Trivy/Grype/SARIF reports, and makes missing artifact output fatal. Build/test/publication/signature/aggregate jobs compare equal to the base; runtime inputs, updater, shell, CA, VEX and exceptions are unchanged.

## Results

- `actionlint`: pass; `zizmor --offline`: zero findings, matching baseline.
- Pinned image-pipeline evaluator `go test ./...`: pass.
- Eight action/evaluator mode test groups: pass. Synthetic findings from both scanners at UNKNOWN/LOW/MEDIUM/HIGH/CRITICAL remain in SARIF with exit 0 in inform mode; gate control exits 1. Secrets at all five severities, scanner execution/conversion failures, missing/invalid/empty scanner reports and SARIF write/validation failures remain fatal.
- Real pinned Trivy 0.70.0 filesystem secret scan, no VEX: five synthetic secrets detected, one at each severity. This verifies the severity environment separately from mocked scanner execution. Custom secret patterns exist only in this isolated fixture, not product configuration.
- Existing pinned-action CI: https://github.com/StackVista/image-pipeline/actions/runs/29080688464 (Action unit tests SUCCESS) and https://github.com/StackVista/image-pipeline/actions/runs/29080688435 (Evaluator CI SUCCESS).
- Exact-head process-agent CI: https://github.com/StackVista/stackstate-process-agent/actions/runs/37281856722. See the final PR description for the latest CI state.

Repository API reports `has_wiki: false`; no AGENTS files exist in the repository or ancestor directories. README, PR conventions, workflow history and the pinned action/evaluator source were inspected. The only open unrelated PR was updater #309.

This is isolated policy validation, not another CVE run. Closed cve-reporter#69 and unrelated delivery holds were not changed. No merge, release, tag, deployment, VEX, ignore, suppression or exception change was performed.

## Reproduction

Download StackVista/image-pipeline at `6284a6fc006a7cc46a7f00d02c50d5f21b117b63` and build its evaluator to this directory as `image-pipeline-evaluate`. The adjacent scripts are verbatim extracted action steps plus the product workflow report-validator. Run `python test_modes.py`; this uses scanner stubs and the real evaluator. `mode-tests.txt`, `evaluator-tests.txt`, lint output and the real secret scanner output are retained separately from the product diff.

## Independent-review handoff

Target existing planner `d79c6920f8cb46c3a8f9a76eb54286c3` for independent review. Dispatch is unavailable in this session: multi-agent send reports agent not found; no session-send tool is advertised; the CLI API read returns HTTP 401; the browser has no connected renderer. No access or infrastructure changes were made. The exact head, PR, intake, tests and CI above form the handoff; independent review is still required.
