"""Run the generated collector with every network command replaced by a mock.

These regressions exercise the actual generated Bash program, including its
errexit/pipefail behavior. No network access or installed scanners are needed.
"""
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

MOCK_COMMANDS = r'''
mock_log() {
    printf '%s' "$1" >> "$MOCK_LOG"
    shift
    printf '\t%s' "$@" >> "$MOCK_LOG"
    printf '\n' >> "$MOCK_LOG"
}
nmap() {
    mock_log nmap "$@"
    local normal='' xml='' option ports="${MOCK_PORTS:-80}"
    while [ "$#" -gt 0 ]; do
        option="$1"; shift
        case "$option" in
            -oN) normal="$1"; shift ;;
            -oX) xml="$1"; shift ;;
        esac
    done
    if [ -n "$normal" ]; then
        : > "$normal"
        if [[ "$normal" != *udp* ]]; then
            if [ "$ports" != none ]; then
                for port in ${ports//,/ }; do
                    printf '%s/tcp open http Fixture server 1.2\n' "$port" >> "$normal"
                done
            fi
            # This state must not be mistaken for confirmed open TCP ports.
            printf '9999/tcp open|filtered unknown\n' >> "$normal"
        fi
    fi
    [ -z "$xml" ] || printf '<nmaprun/>\n' > "$xml"
    return 0
}
curl() {
    mock_log curl "$@"
    local output='' status=false headers=false url='' option
    while [ "$#" -gt 0 ]; do
        option="$1"; shift
        case "$option" in
            -o) output="$1"; shift ;;
            -w) status=true; shift ;;
            -H|--resolve|--connect-timeout|--max-time) shift ;;
            -I) headers=true ;;
            http://*|https://*) url="$option" ;;
        esac
    done
    if [ "$status" = true ]; then
        if [[ "$url" == http://* ]]; then printf '%s' "${MOCK_HTTP_STATUS:-404}"; else printf 000; fi
    elif [ -n "$output" ] && [ "$output" != /dev/null ]; then
        printf '%s\n' "${MOCK_HTTP_BODY:-fixture password marker}" > "$output"
    elif [ "$headers" = true ]; then
        printf 'HTTP/1.1 404 Not Found\nServer: FixtureWeb\n'
    fi
}
ffuf() {
    mock_log ffuf "$@"
    local output=''
    while [ "$#" -gt 0 ]; do
        if [ "$1" = -o ]; then output="$2"; shift; fi
        shift
    done
    if [ -n "$output" ]; then printf '{"results":[]}\n' > "$output"; fi
    return "${MOCK_FFUF_EXIT:-0}"
}
# Shell functions win over every real executable on PATH. timeout is mocked as
# well so it cannot bypass these functions by spawning a real network program.
timeout() { shift; "$@"; }
for tool in whatweb feroxbuster nikto dig dnsrecon gobuster smbclient \
    enum4linux-ng enum4linux smbmap showmount rpcinfo snmpwalk onesixtyone \
    ldapsearch zip nc openssl ftp httpx nuclei netexec crackmapexec droopescan \
    wpscan joomscan sudo; do
    eval "$tool() { mock_log $tool \"\$@\"; return 0; }"
done
'''


def bash_path(path):
    """Git Bash accepts C:/ paths, whereas Windows backslashes are literals."""
    return Path(path).as_posix()


@unittest.skipUnless(BASH, "Bash is required for collector tests")
class CollectionWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.bin_env = self.root / "mock-commands.sh"
        self.bin_env.write_text(MOCK_COMMANDS, encoding="utf-8", newline="\n")
        self.log = self.root / "commands.log"
        self.env = dict(os.environ, HTB_LABS_ROOT=bash_path(self.root / "labs with spaces"),
                        HTB_PYTHON="missing-python-for-test", BASH_ENV=bash_path(self.bin_env),
                        MOCK_LOG=bash_path(self.log), WEB_ASSESS="0")
        created = self.call(ROOT / "htb-init.sh", "fixture", "192.0.2.10")
        self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
        self.workspace = self.root / "labs with spaces" / "fixture"

    def tearDown(self):
        self.temp.cleanup()

    def call(self, script, *args):
        return subprocess.run([BASH, bash_path(script), *map(str, args)], env=self.env,
                              cwd=self.root, capture_output=True, text=True,
                              encoding="utf-8", timeout=60)

    def recon(self):
        result = self.call(self.workspace / "recon.sh")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Recon finished at:", result.stdout)
        return result

    def commands(self, name):
        if not self.log.exists():
            return []
        return [line.split("\t")[1:] for line in self.log.read_text().splitlines()
                if line.split("\t")[0] == name]

    def mock_assessor(self):
        """Stub the launcher for collector integration, never invoke a scanner."""
        (self.workspace / "web-assess.sh").write_text(r'''#!/usr/bin/env bash
set -euo pipefail
mock_log web-assess "$@"
# Capture exactly what was available when recon dispatched this stage.
cat enum/web/live-web-urls.txt > assessor-live-input.txt
cat enum/web/discovered-host-web-urls.txt > assessor-vhost-input.txt
exit "${MOCK_ASSESS_STATUS:-0}"
''', encoding="utf-8", newline="\n")

    def test_generated_assessor_is_copied_and_runs_dry_from_another_directory(self):
        self.assertEqual((self.workspace / "web-assess.py").read_bytes(),
                         (ROOT / "web-assess.py").read_bytes())
        self.assertTrue((self.workspace / "web-assess.sh").is_file())
        self.env["HTB_PYTHON"] = bash_path(sys.executable)
        target = "http://fixture.htb/items?q=example"
        result = self.call(self.workspace / "web-assess.sh", "--dry-run", "--url", target)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        reports = list((self.workspace / "enum/web/assessments").glob("*/report.json"))
        self.assertEqual(len(reports), 1)
        report = json.loads(reports[0].read_text(encoding="utf-8"))
        self.assertEqual(report["status"], "planned")
        self.assertEqual(report["targets"], [target])
        self.assertEqual({stage["name"] for stage in report["stages"]}, {"http", "dast"})
        self.assertTrue(all(stage["status"] == "planned" for stage in report["stages"]))
        self.assertFalse((self.root / "enum").exists())
        self.assertFalse(self.commands("nuclei"))
        self.assertFalse(self.commands("curl"))

    def test_auto_assessor_runs_once_after_discovery_and_preserves_status_meaning(self):
        self.mock_assessor()
        self.env["WEB_ASSESS"] = "1"
        for status, expected in ((0, "Automated web assessment finished"),
                                 (1, "Web assessment produced findings"),
                                 (2, "Web assessment incomplete (exit 2)")):
            with self.subTest(status=status):
                if self.log.exists():
                    self.log.unlink()
                self.env["MOCK_ASSESS_STATUS"] = str(status)
                result = self.recon()
                self.assertEqual(len(self.commands("web-assess")), 1)
                self.assertIn(expected, result.stdout)
                self.assertIn("http://192.0.2.10:80", (self.workspace / "assessor-live-input.txt").read_text())
                self.assertIn("http://fixture.htb", (self.workspace / "assessor-vhost-input.txt").read_text())
                self.assertNotIn("--dry-run", self.commands("web-assess")[0])
                self.assertLess(result.stdout.index("Web application assessment"),
                                result.stdout.index("7. SMB enumeration"))
                # Recon continues and archives even when findings or an error
                # were returned, but the distinct warning is retained above.
                self.assertTrue(self.commands("zip"))

    def test_web_assess_zero_disables_automatic_assessor(self):
        self.mock_assessor()
        self.env["WEB_ASSESS"] = "0"
        result = self.recon()
        self.assertIn("Web assessment disabled or no web URLs discovered", result.stdout)
        self.assertFalse(self.commands("web-assess"))
        self.assertFalse((self.workspace / "assessor-live-input.txt").exists())
        self.assertTrue((self.workspace / "enum/web/live-web-urls.txt").read_text())

    def test_web_enum_zero_disables_cms_scanners_and_nikto(self):
        self.env.update(WEB_ENUM="0", WEB_ASSESS="0", MOCK_HTTP_BODY="Drupal WordPress Joomla swagger")
        self.recon()
        profiles = list((self.workspace / "enum/web").glob("technology-profile-*.txt"))
        self.assertTrue(profiles)
        detected = profiles[0].read_text()
        for cms in ("drupal", "wordpress", "joomla", "api"):
            self.assertIn(cms, detected)
        for tool in ("ffuf", "feroxbuster", "nikto", "droopescan", "nuclei", "wpscan", "joomscan"):
            self.assertFalse(self.commands(tool), f"{tool} must honor WEB_ENUM=0")
        self.assertTrue((self.workspace / "enum/web/live-web-urls.txt").read_text())

    def test_enabled_assessor_is_skipped_without_live_web_targets(self):
        self.mock_assessor()
        self.env.update(WEB_ASSESS="1", MOCK_PORTS="22", MOCK_HTTP_STATUS="000")
        result = self.recon()
        self.assertIn("Web assessment disabled or no web URLs discovered", result.stdout)
        self.assertFalse(self.commands("web-assess"))

    def test_vulnerability_and_safe_scans_detect_versions_in_the_same_invocation(self):
        self.recon()
        scans = self.commands("nmap")
        for scripts in ("vuln", "default,safe"):
            scan = next(args for args in scans if "--script" in args and
                        args[args.index("--script") + 1] == scripts)
            self.assertIn("-sV", scan)
            self.assertEqual(scan[scan.index("-p") + 1], "80")
        for stem in ("tcp-services", "tcp-vuln"):
            self.assertTrue((self.workspace / "scans" / (stem + ".xml")).exists())
        self.assertEqual((self.workspace / "scans/open-tcp-ports.txt").read_text().strip(), "80")

    def test_http_404_is_live_and_evidence_patterns_match_alternatives(self):
        self.recon()
        self.assertIn("http://192.0.2.10:80", (self.workspace / "enum/web/live-web-urls.txt").read_text())
        self.assertIn("http://fixture.htb", (self.workspace / "enum/web/discovered-host-web-urls.txt").read_text())
        findings = (self.workspace / "enum/interesting-grep.txt").read_text()
        self.assertIn("fixture password marker", findings)
        summary = (self.workspace / "summary.md").read_text()
        headers_section = summary.split("## Interesting Web Headers", 1)[1].split("## Ferox Results", 1)[0]
        self.assertIn("Server: FixtureWeb", headers_section)

    def test_target_without_a_common_web_port_finishes_under_pipefail(self):
        self.env.update(MOCK_PORTS="22", MOCK_HTTP_STATUS="000")
        self.recon()
        self.assertIn("22", (self.workspace / "scans/open-tcp-ports.txt").read_text())
        self.assertFalse(self.commands("curl"))

    def test_discovered_vhosts_probe_nonstandard_live_web_ports(self):
        self.env["MOCK_PORTS"] = "12345"
        self.recon()
        urls = (self.workspace / "enum/web/discovered-host-web-urls.txt").read_text()
        self.assertIn("http://fixture.htb:12345", urls)

    def test_priority_vhost_wordlist_runs_again_on_a_later_recon(self):
        # Reproduce a marker left behind by an older collector after a failure.
        (self.workspace / "enum/web/.ffuf-vhost-http-80-fixture_htb-priority-vhosts_txt.done").touch()
        self.recon()
        first = len(self.commands("ffuf"))
        self.assertGreater(first, 0)
        self.assertTrue(any("enum/dns/priority-vhosts.txt" in args for args in self.commands("ffuf")))
        self.recon()
        self.assertEqual(len(self.commands("ffuf")), first * 2)

    def test_no_open_ports_replaces_old_open_port_manifest(self):
        (self.workspace / "scans/open-tcp-ports.txt").write_text("80,443\n")
        for manifest in ("live-web-urls.txt", "discovered-host-web-urls.txt"):
            (self.workspace / "enum/web" / manifest).write_text("http://old-target.htb\n")
        self.env["MOCK_PORTS"] = "none"
        result = self.call(self.workspace / "recon.sh")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.workspace / "scans/open-tcp-ports.txt").read_text(), "")
        for manifest in ("live-web-urls.txt", "discovered-host-web-urls.txt"):
            self.assertEqual((self.workspace / "enum/web" / manifest).read_text(), "")
        self.assertIn("No open TCP ports", (self.workspace / "summary.md").read_text())


if __name__ == "__main__":
    unittest.main()
