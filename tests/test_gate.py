"""Unit tests for tools/gate.py using real semgrep/checkov output (tests/fixtures) and format-faithful synthetic samples."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests/fixtures"
sys.path.insert(0, str(ROOT / "tools"))
import gate  # noqa: E402

POLICY = yaml.safe_load((ROOT / "policy/gate-policy.yml").read_text())
TODAY = date(2026, 10, 30)
EMPTY_TRIVY = {"Results": []}


def reports(**files):
    """Create a reports dir. Values are fixture file names (str) or python objects to dump."""
    d = Path(tempfile.mkdtemp(prefix="gate-"))
    for key, val in files.items():
        key = key.replace("_", "-")
        if isinstance(val, str):
            shutil.copy(FIX / val, d / f"{key}.json")
        else:
            (d / f"{key}.json").write_text(json.dumps(val))
    return d


def clean(**over):
    base = dict(semgrep="semgrep-clean.json", gitleaks=[], trivy_fs=EMPTY_TRIVY, trivy_image=EMPTY_TRIVY, checkov="checkov-good.json")
    base.update(over)
    return reports(**base)


def run(policy, rdir):
    out, blockers, warns = gate.evaluate(policy, rdir, TODAY)
    code = 2 if out.missing else 1 if (blockers or out.problems) else 0
    return code, out, blockers, warns


class GateTests(unittest.TestCase):
    def test_clean_run_passes(self):
        code, *_ = run(POLICY, clean())
        self.assertEqual(code, 0)

    def test_vulnerable_app_sast_blocks_with_critical_override(self):
        code, _, blockers, warns = run(POLICY, clean(semgrep="semgrep-vulnerable.json"))
        self.assertEqual(code, 1)
        sev = {f.rule.split(".")[-1]: f.severity for f in blockers}
        self.assertEqual(sev["taint-to-sql"], "critical")
        self.assertEqual(sev["hardcoded-secret"], "critical")
        self.assertEqual((len(blockers), len(warns)), (7, 3))   # 7 ERROR-level block; 3 WARNING-level (medium) only warn

    def test_bad_dockerfile_blocks_on_overridden_checks(self):
        code, _, blockers, warns = run(POLICY, clean(checkov="checkov-bad.json"))
        self.assertEqual(code, 1)
        self.assertEqual({f.rule for f in blockers}, {"CKV_DOCKER_1", "CKV_DOCKER_3"})
        self.assertTrue(any(f.rule == "CKV_DOCKER_7" for f in warns))   # medium: warns but does not block

    def test_secret_blocks(self):
        leak = [{"RuleID": "generic-api-key", "Description": "Generic API Key", "File": "app/src/Config.php", "StartLine": 9}]
        code, _, blockers, _ = run(POLICY, clean(gitleaks=leak))
        self.assertEqual((code, blockers[0].severity), (1, "critical"))

    def test_trivy_high_blocks_medium_warns(self):
        t = {"Results": [{"Target": "composer.lock", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2099-0001", "PkgName": "acme/lib", "InstalledVersion": "1.0", "Severity": "HIGH", "Title": "RCE"},
            {"VulnerabilityID": "CVE-2099-0002", "PkgName": "acme/lib", "InstalledVersion": "1.0", "Severity": "MEDIUM", "Title": "DoS"}]}]}
        code, _, blockers, warns = run(POLICY, clean(trivy_fs=t))
        self.assertEqual(code, 1)
        self.assertEqual([f.rule for f in blockers], ["CVE-2099-0001"])
        self.assertEqual([f.rule for f in warns], ["CVE-2099-0002"])

    def test_medium_only_passes(self):
        t = {"Results": [{"Target": "x", "Vulnerabilities": [{"VulnerabilityID": "CVE-2099-0002", "PkgName": "p", "InstalledVersion": "1", "Severity": "MEDIUM", "Title": "DoS"}]}]}
        self.assertEqual(run(POLICY, clean(trivy_image=t))[0], 0)

    def test_missing_required_report_fails_closed(self):
        d = clean()
        (d / "gitleaks.json").unlink()
        code, out, *_ = run(POLICY, d)
        self.assertEqual(code, 2)
        self.assertIn("gitleaks", out.missing[0])

    def test_unparseable_required_report_fails_closed(self):
        d = clean()
        (d / "semgrep.json").write_text("{not json")
        self.assertEqual(run(POLICY, d)[0], 2)

    def _with_waiver(self, **w):
        p = dict(POLICY)
        p["exceptions"] = [dict({"id": "CVE-2099-0001", "reason": "not reachable", "owner": "sec", "expires": "2026-12-01"}, **w)]
        return p

    HIGH = {"Results": [{"Target": "composer.lock", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2099-0001", "PkgName": "acme/lib", "InstalledVersion": "1.0", "Severity": "HIGH", "Title": "RCE"}]}]}

    def test_valid_waiver_unblocks(self):
        code, _, blockers, _ = run(self._with_waiver(), clean(trivy_fs=self.HIGH))
        self.assertEqual((code, blockers), (0, []))

    def test_expired_waiver_fails_build_even_without_findings(self):
        code, out, *_ = run(self._with_waiver(expires="2026-10-01"), clean())
        self.assertEqual(code, 1)
        self.assertIn("EXPIRED", out.problems[0])

    def test_waiver_without_owner_is_rejected_and_does_not_waive(self):
        p = self._with_waiver()
        del p["exceptions"][0]["owner"]
        code, out, blockers, _ = run(p, clean(trivy_fs=self.HIGH))
        self.assertEqual(code, 1)
        self.assertTrue(blockers and "missing owner" in out.problems[0])

    def test_waiver_too_far_in_future_rejected(self):
        code, out, *_ = run(self._with_waiver(expires="2027-06-01"), clean(trivy_fs=self.HIGH))
        self.assertEqual(code, 1)
        self.assertIn("days away", out.problems[0])

    def test_waiver_scoped_to_path_does_not_cover_other_files(self):
        code, _, blockers, _ = run(self._with_waiver(paths=["other/*.lock"]), clean(trivy_fs=self.HIGH))
        self.assertEqual((code, len(blockers)), (1, 1))

    def test_cli_exit_codes(self):
        cmd = [sys.executable, str(ROOT / "tools/gate.py"), "--policy", str(ROOT / "policy/gate-policy.yml"), "--today", "2026-10-30"]
        self.assertEqual(subprocess.run(cmd + ["--reports", str(clean())], capture_output=True).returncode, 0)
        self.assertEqual(subprocess.run(cmd + ["--reports", str(clean(semgrep="semgrep-vulnerable.json"))], capture_output=True).returncode, 1)
        empty = Path(tempfile.mkdtemp())
        self.assertEqual(subprocess.run(cmd + ["--reports", str(empty)], capture_output=True).returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
