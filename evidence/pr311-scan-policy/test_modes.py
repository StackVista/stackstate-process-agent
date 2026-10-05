#!/usr/bin/env python3
"""One-off validation of the pinned scan-image scripts and caller report contract."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
SEVERITIES = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
IMAGE = "quay.io/stackstate/stackstate-k8s-process-agent:policy-fixture"
MOCK = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
scanner = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
kind = "grype" if scanner == "grype" else ("convert" if args[0] == "convert" else ("secrets" if "secret" in args else "trivy"))
with open("commands.jsonl", "a") as log:
    log.write(json.dumps({"kind": kind, "args": args, "severity": os.environ["TRIVY_SEVERITY"]}) + "\n")
failure = os.environ.get("FAILURE", "")
if failure == kind + "-execution":
    sys.exit(17)
if kind == "convert":
    sys.exit(0)
path = pathlib.Path("reports") / {"secrets":"trivy-secrets.json", "trivy":"trivy.json", "grype":"grype.json"}[kind]
if failure == kind + "-missing":
    sys.exit(0)
if failure == kind + "-invalid":
    path.write_text("{invalid json")
    sys.exit(0)
if failure == kind + "-empty-object":
    path.write_text("{}")
    sys.exit(0)
if kind == "grype":
    report = {"matches": [{"vulnerability": {"id": "CVE-2099-GRYPE-" + s.upper(), "severity": s},
                          "artifact": {"name": "fixture-grype-" + s, "version": "1.0"}} for s in ["Unknown", "Low", "Medium", "High", "Critical"]]}
else:
    result = {"Target": "fixture"}
    if kind == "trivy":
        result["Vulnerabilities"] = [{"VulnerabilityID": "CVE-2099-TRIVY-" + s, "PkgName": "fixture-trivy-" + s, "InstalledVersion": "1.0", "Severity": s}
                                    for s in ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]]
    elif os.environ.get("SECRET_SEVERITY"):
        result["Secrets"] = [{"RuleID":"synthetic-secret", "Severity":os.environ["SECRET_SEVERITY"], "Match":"synthetic-value"}]
    report = {"SchemaVersion":2, "ArtifactName": os.environ["INPUT_IMAGE"], "Results":[result]}
path.write_text(json.dumps(report))
'''


class ModeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.tmp.name)
        (self.work / "bin").mkdir()
        (self.work / "reports").mkdir()
        (self.work / "reports/grype-vex-documents.txt").write_text("/dev/null\n")
        for name in ["trivy", "grype"]:
            path = self.work / "bin" / name
            path.write_text(MOCK)
            path.chmod(0o755)
        sleep = self.work / "bin/sleep"
        sleep.write_text("#!/bin/sh\nexit 0\n")
        sleep.chmod(0o755)
        shutil.copy(ROOT / "image-pipeline-evaluate", self.work / "bin/image-pipeline-evaluate")
        self.env = dict(os.environ, PATH=str(self.work / "bin") + ":" + os.environ["PATH"],
                        INPUT_IMAGE=IMAGE, INPUT_SEVERITY=",".join(SEVERITIES), TRIVY_SEVERITY=",".join(SEVERITIES),
                        INPUT_SKIP_FILES="", INPUT_MODE="inform", INPUT_EXCEPTIONS_PATH="",
                        SARIF_PATH="reports/image-pipeline.sarif", GITHUB_OUTPUT=str(self.work / "outputs"))
        self.env.pop("SECRET_SEVERITY", None)
        self.env.pop("FAILURE", None)

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, name):
        return subprocess.run(["bash", "-e", str(ROOT / (name + ".sh"))], cwd=self.work,
                              env=self.env, capture_output=True, text=True)

    def pipeline(self):
        for script in ["secrets", "trivy", "grype", "evaluate"]:
            result = self.run_script(script)
            if result.returncode:
                return script, result
        outputs = dict(line.split("=", 1) for line in (self.work / "outputs").read_text().splitlines())
        self.env["EXIT_CODE"] = outputs["exit-code"]
        result = self.run_script("gate")
        if result.returncode:
            return "gate", result
        return "validate", self.run_script("validate")

    def test_inform_keeps_all_scanner_findings_and_sarif(self):
        stage, result = self.pipeline()
        self.assertEqual(result.returncode, 0, stage + result.stderr)
        sarif = json.loads((self.work / "reports/image-pipeline.sarif").read_text())
        self.assertEqual(len(sarif["runs"][0]["results"]), 10)
        ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
        self.assertEqual(ids, {"CVE-2099-" + scanner + "-" + severity
                               for scanner in ["TRIVY", "GRYPE"] for severity in SEVERITIES})
        calls = [json.loads(line) for line in (self.work / "commands.jsonl").read_text().splitlines()]
        self.assertEqual({c["kind"] for c in calls}, {"secrets", "trivy", "convert", "grype"})
        self.assertTrue(all(c["severity"] == ",".join(SEVERITIES) for c in calls))

    def test_gate_control_blocks_vulnerabilities(self):
        self.env["INPUT_MODE"] = "gate"
        stage, result = self.pipeline()
        self.assertEqual(stage, "gate")
        self.assertEqual(result.returncode, 1)
        self.assertTrue((self.work / "reports/image-pipeline.sarif").is_file())

    def test_secrets_block_at_every_severity(self):
        for severity in SEVERITIES:
            with self.subTest(severity=severity):
                self.env["SECRET_SEVERITY"] = severity
                stage, result = self.pipeline()
                self.assertEqual(stage, "secrets")
                self.assertNotEqual(result.returncode, 0)

    def test_scanner_execution_and_conversion_errors_block(self):
        for kind in ["secrets", "trivy", "grype", "convert"]:
            with self.subTest(kind=kind):
                self.env["FAILURE"] = kind + "-execution"
                stage, result = self.pipeline()
                self.assertNotEqual(result.returncode, 0, stage)
                if kind in ["secrets", "trivy"]:
                    self.assertIn("after 3 attempts", result.stdout)

    def test_required_scanner_reports_fail_closed(self):
        for kind in ["secrets", "trivy", "grype"]:
            for failure in ["invalid", "missing", "empty-object"]:
                with self.subTest(kind=kind, failure=failure):
                    for path in (self.work / "reports").glob("*.json"):
                        path.unlink()
                    (self.work / "outputs").unlink(missing_ok=True)
                    self.env["FAILURE"] = kind + "-" + failure
                    stage, result = self.pipeline()
                    self.assertNotEqual(result.returncode, 0, stage)

    def test_sarif_output_errors_block_in_inform(self):
        self.env["SARIF_PATH"] = "missing-directory/report.sarif"
        stage, result = self.pipeline()
        self.assertEqual(stage, "gate")
        self.assertEqual(result.returncode, 2)

    def test_sarif_report_validation_blocks_invalid_or_missing(self):
        _, result = self.pipeline()
        self.assertEqual(result.returncode, 0)
        path = self.work / "reports/image-pipeline.sarif"
        for content in ["{invalid json", "{}", '{"version":"2.1.0","runs":[]}']:
            with self.subTest(content=content):
                path.write_text(content)
                self.assertNotEqual(self.run_script("validate").returncode, 0)
        path.unlink()
        self.assertNotEqual(self.run_script("validate").returncode, 0)

    def test_empty_clean_trivy_results_are_valid(self):
        _, result = self.pipeline()
        self.assertEqual(result.returncode, 0)
        for name in ["trivy.json", "trivy-secrets.json"]:
            for results in [None, []]:
                (self.work / "reports" / name).write_text(json.dumps(
                    {"SchemaVersion": 2, "ArtifactName": IMAGE, "Results": results}))
                self.assertEqual(self.run_script("validate").returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
