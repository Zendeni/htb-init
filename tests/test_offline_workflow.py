"""Integration tests exercise only offline dispatch, never the collector."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get("HTB_TEST_BASH") or shutil.which("bash")


@unittest.skipUnless(BASH, "Bash is required for initializer dispatch tests")
class OfflineWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp.name) / "workspace with spaces"
        self.workspace.mkdir()
        (self.workspace / ".target.env").write_text('BOX="example"\nIP="192.0.2.10"\nHOST="example.test"\n', encoding="utf-8")
        (self.workspace / "scans").mkdir()
        (self.workspace / "scans" / "services.txt").write_text("Nmap scan report for 192.0.2.10\n21/tcp open ftp Example service\n", encoding="utf-8")
        self.env = dict(os.environ, HTB_PYTHON=sys.executable, HTB_LABS_ROOT=str(self.workspace / "must-not-create"))

    def tearDown(self):
        self.temp.cleanup()

    def call(self, *args, script=None, cwd=None):
        return subprocess.run([BASH, str(script or ROOT / "htb-init.sh"), *map(str, args)],
                              env=self.env, cwd=cwd, text=True, encoding="utf-8", capture_output=True, timeout=30)

    def test_help_does_not_require_scopelens_or_create_workspace(self):
        self.env["HTB_PYTHON"] = "missing-python-for-test"
        result = self.call("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--inspect", result.stdout)
        self.assertFalse((self.workspace / "must-not-create").exists())

    def test_missing_dependency_has_actionable_error(self):
        self.env["HTB_PYTHON"] = "missing-python-for-test"
        result = self.call("--inspect", self.workspace)
        self.assertEqual(result.returncode, 2)
        self.assertIn("ScopeLens 0.2+", result.stderr)

    def test_diagnostics_and_rule_catalog_share_installed_package(self):
        doctor = self.call("--doctor")
        self.assertEqual(doctor.returncode, 0, doctor.stderr)
        self.assertIn("ScopeLens", doctor.stdout)
        rules = self.call("--rules")
        self.assertEqual(rules.returncode, 0, rules.stderr)
        self.assertIn("SL001", rules.stdout)
        self.assertFalse((self.workspace / "must-not-create").exists())

    def test_unknown_option_is_rejected_before_dependency_check(self):
        self.env["HTB_PYTHON"] = "missing-python-for-test"
        result = self.call("--reveiw", self.workspace)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Unknown option: --reveiw", result.stderr)
        self.assertNotIn("requires ScopeLens", result.stderr)
        self.assertFalse((self.workspace / "must-not-create").exists())

    def test_copied_entrypoint_ignores_workspace_python_modules(self):
        entrypoint = self.workspace / "htb-init.sh"
        shutil.copyfile(ROOT / "htb-init.sh", entrypoint)
        (self.workspace / "scopelens.py").write_text(
            'raise RuntimeError("workspace module must never execute")\n', encoding="utf-8")
        result = self.call("--inspect", self.workspace, "--json", script=entrypoint, cwd=self.workspace)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["workspace"], str(self.workspace.resolve()))

    def test_review_usage_errors_preserve_exit_code_and_do_not_write_reports(self):
        result = self.call("--review", self.workspace, "--format", "invalid")
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid choice", result.stderr)
        self.assertFalse((self.workspace / "reports").exists())

    def test_prepare_preserves_custom_scope_and_notes(self):
        scope = '{"include":["192.0.2.10"],"exclude":["192.0.2.99"]}\n'
        (self.workspace / "scope.json").write_text(scope, encoding="utf-8")
        (self.workspace / "notes.md").write_text("Keep my notes", encoding="utf-8")
        for _ in range(2):
            result = self.call("--prepare", self.workspace)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.workspace / "scope.json").read_text(), scope)
        self.assertEqual((self.workspace / "notes.md").read_text(), "Keep my notes")
        self.assertTrue((self.workspace / "analyze.sh").is_file())
        self.assertTrue((self.workspace / "inspect.sh").is_file())

    def test_review_inspect_and_latest_baseline_are_offline(self):
        self.assertEqual(self.call("--prepare", self.workspace).returncode, 0)
        first = self.call("--review", self.workspace, "--fail-on", "medium")
        self.assertEqual(first.returncode, 1, first.stderr)
        second = self.call("--review", self.workspace, "--baseline", "latest")
        self.assertEqual(second.returncode, 0, second.stderr)
        reports = sorted((self.workspace / "reports").glob("*/report.json"))
        self.assertEqual(len(reports), 2)
        payloads = [json.loads(p.read_text(encoding="utf-8")) for p in reports]
        self.assertTrue(any(p["diff"] is not None for p in payloads))
        self.assertEqual({p["summary"]["services"] for p in payloads}, {1})
        inspected = self.call("--inspect", self.workspace, "--json")
        self.assertEqual(inspected.returncode, 0, inspected.stderr)
        info = json.loads(inspected.stdout)
        self.assertEqual(len(info["reports"]), 2)
        self.assertFalse((self.workspace / "recon.sh").exists())
        self.assertFalse((self.workspace / "must-not-create").exists())

    def test_generated_helpers_run_from_another_directory(self):
        self.assertEqual(self.call("--prepare", self.workspace).returncode, 0)
        review = self.call(script=self.workspace / "analyze.sh")
        self.assertEqual(review.returncode, 0, review.stderr)
        inspect = self.call("--json", script=self.workspace / "inspect.sh")
        self.assertEqual(inspect.returncode, 0, inspect.stderr)
        self.assertEqual(len(json.loads(inspect.stdout)["reports"]), 1)

    def test_environment_metadata_is_never_executed(self):
        marker = self.workspace / "unexpected-execution"
        (self.workspace / ".target.env").write_text(
            'BOX="example"\nIP="192.0.2.10"\nHOST="example.test"\n'
            f'IGNORED="$(touch {marker.as_posix()})"\n', encoding="utf-8")
        result = self.call("--prepare", self.workspace)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.call("--inspect", self.workspace, "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())

    def test_invalid_creation_inputs_fail_before_generation(self):
        for name, address in (("..", "192.0.2.10"), (".", "192.0.2.10"), ("../escape", "192.0.2.10"), ("example", "999.1.1.1")):
            with self.subTest(name=name, address=address):
                self.assertNotEqual(self.call(name, address).returncode, 0)
        self.assertFalse((self.workspace / "must-not-create").exists())


if __name__ == "__main__":
    unittest.main()
