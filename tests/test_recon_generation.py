"""Regression tests for generated recon safety and vulnerability stages."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get("HTB_TEST_BASH") or shutil.which("bash")


@unittest.skipUnless(BASH, "Bash is required for recon generation tests")
class ReconGenerationTests(unittest.TestCase):
    def test_one_launch_recon_has_live_vulnerability_enrichment(self):
        with tempfile.TemporaryDirectory() as temp:
            labs_root = Path(temp) / "labs"
            env = dict(
                os.environ,
                HTB_LABS_ROOT=str(labs_root),
                HTB_PYTHON="missing-python-for-test",
            )

            result = subprocess.run(
                [BASH, str(ROOT / "htb-init.sh"), "example", "192.0.2.10"],
                env=env,
                text=True,
                encoding="utf-8",
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            workspace = labs_root / "example"
            recon = (workspace / "recon.sh").read_text(encoding="utf-8")
            archive = (workspace / "zip-recon.sh").read_text(encoding="utf-8")
            assessor = (workspace / "web-assess.py").read_text(encoding="utf-8")

            self.assertIn('ONLINE_VULN_CHECK="${ONLINE_VULN_CHECK:-1}"', recon)
            self.assertIn('VHOST_SUFFIXES="${VHOST_SUFFIXES:-htb,vl,local}"', recon)
            self.assertIn("is_vhost_base_candidate", recon)
            self.assertIn('NIKTO_MAXTIME="${NIKTO_MAXTIME:-600}"', recon)
            self.assertIn('NUCLEI_MAXTIME="${NUCLEI_MAXTIME:-600}"', recon)
            self.assertIn('WEB_ASSESS="${WEB_ASSESS:-1}"', recon)
            self.assertIn('WEB_ASSESS_MAXTIME="${WEB_ASSESS_MAXTIME:-2100}"', recon)
            self.assertIn('NMAP_MAXTIME="${NMAP_MAXTIME:-900}"', recon)
            self.assertIn('SERVICE_ENUM_MAXTIME="${SERVICE_ENUM_MAXTIME:-300}"', recon)
            self.assertIn('WEB_PROBE_MAXTIME="${WEB_PROBE_MAXTIME:-120}"', recon)
            self.assertIn('ANALYZER_MAXTIME="${ANALYZER_MAXTIME:-900}"', recon)
            self.assertIn('ARCHIVE_MAXTIME="${ARCHIVE_MAXTIME:-300}"', recon)
            self.assertIn('UPDATE_SCANNER_DATA="${UPDATE_SCANNER_DATA:-1}"', recon)
            self.assertIn("refresh_scanner_data", recon)
            self.assertIn("nuclei -update-templates", recon)
            self.assertIn('timeout --signal=TERM --kill-after=10', recon)
            self.assertIn('run_with_timeout "$NIKTO_MAXTIME" nikto', recon)
            self.assertIn('run_with_timeout "$NUCLEI_MAXTIME" nuclei', recon)
            self.assertIn('run_with_timeout "$NMAP_MAXTIME" nmap', recon)
            self.assertIn('run_with_timeout "$ANALYZER_MAXTIME" python3', recon)
            self.assertIn('run_with_timeout "$ARCHIVE_MAXTIME" ./zip-recon.sh', recon)
            self.assertIn('run_with_timeout "$WEB_ASSESS_MAXTIME" bash ./web-assess.sh', recon)
            self.assertIn("-sV --script vuln", recon)
            self.assertIn('"-dast"', assessor)
            self.assertIn("SSRF", assessor)
            self.assertIn("XXE", assessor)
            self.assertIn("XSS", assessor)
            self.assertIn("run_online_vuln_analysis", recon)
            self.assertIn("--online-vuln-check", recon)
            self.assertIn("show_progress 22", recon)
            self.assertIn("Progress: 100%", recon)
            self.assertIn("recon-analysis.md", archive)
            self.assertIn("web-assess.py", archive)
            self.assertTrue((workspace / "tools" / "analyze-recon.py").is_file())
            self.assertTrue((workspace / "web-assess.sh").is_file())

            syntax = subprocess.run(
                [BASH, "-n", str(workspace / "recon.sh")],
                text=True,
                encoding="utf-8",
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(syntax.returncode, 0, syntax.stderr)


if __name__ == "__main__":
    unittest.main()
