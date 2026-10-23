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
    if [[ "${MOCK_NMAP_FAIL:-}" == services && "$*" == *scans/tcp-services.txt* ]]; then return "${MOCK_FAILURE_STATUS:-1}"; fi
    if [[ "${MOCK_NMAP_FAIL:-}" == discovery && "$*" == *scans/tcp-full.txt* ]]; then return "${MOCK_FAILURE_STATUS:-124}"; fi
    if [[ -n "${MOCK_NMAP_FAIL_OUTPUT:-}" && "$*" == *"$MOCK_NMAP_FAIL_OUTPUT"* ]]; then return "${MOCK_FAILURE_STATUS:-124}"; fi
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
        if [[ "$normal" == *udp* && "${MOCK_UDP:-}" == 161 ]]; then printf '161/udp %s snmp\n' "${MOCK_UDP_STATE:-open}" > "$normal"; fi
        if [[ "$normal" != *udp* ]]; then
            if [ "$ports" != none ]; then
                for port in ${ports//,/ }; do
                    local service="${MOCK_SERVICE:-http}"
                    if [[ "$port" == 22 && -z "${MOCK_SERVICE:-}" ]]; then service=ssh; fi
                    local mapping
                    for mapping in ${MOCK_SERVICE_MAP//,/ }; do
                        if [[ "$mapping" == "$port="* ]]; then service="${mapping#*=}"; fi
                    done
                    printf '%s/tcp open %s %s\n' "$port" "$service" "${MOCK_PRODUCT:-Fixture server 1.2}" >> "$normal"
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
timeout() {
    while [[ "${1:-}" == --* ]]; do shift; done
    shift
    if [[ "$*" == *tools/analyze-recon.py* ]]; then
        mock_log analyzer "$@"
        if [[ "${MOCK_ANALYZER_EXIT:-0}" != 0 ]]; then return "$MOCK_ANALYZER_EXIT"; fi
    fi
    "$@"
}
for tool in whatweb feroxbuster nikto dig dnsrecon gobuster smbclient \
    enum4linux-ng enum4linux smbmap showmount rpcinfo snmpwalk onesixtyone \
    ldapsearch zip nc openssl ftp httpx nuclei netexec crackmapexec droopescan \
    wpscan joomscan sudo; do
    eval "$tool() { mock_log $tool \"\$@\"; return 0; }"
done
zip() { mock_log zip "$@"; mock_log zip-umask "$(umask)"; if [[ "${MOCK_ZIP_EXIT:-0}" != 0 ]]; then return "$MOCK_ZIP_EXIT"; fi; : > "$2"; }
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
                        MOCK_LOG=bash_path(self.log), WEB_ASSESS="0", ONLINE_VULN_CHECK="0")
        self.env.setdefault("MOCK_SERVICE_MAP", "")
        created = self.call(ROOT / "htb-init.sh", "fixture", "192.0.2.10")
        self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
        self.workspace = self.root / "labs with spaces" / "fixture"
        self.env["HTB_PYTHON"] = bash_path(sys.executable)

    def tearDown(self):
        self.temp.cleanup()

    def call(self, script, *args):
        return subprocess.run([BASH, bash_path(script), *map(str, args)], env=self.env,
                              cwd=self.root, capture_output=True, text=True,
                              encoding="utf-8", timeout=60)

    def recon(self, expected_status=0):
        result = self.call(self.workspace / "recon.sh")
        self.assertEqual(result.returncode, expected_status, result.stdout + result.stderr)
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
                result = self.recon(expected_status=2 if status == 2 else 0)
                self.assertEqual(len(self.commands("web-assess")), 1)
                self.assertIn(expected, result.stdout)
                self.assertIn("http://192.0.2.10:80", (self.workspace / "assessor-live-input.txt").read_text())
                self.assertIn("http://fixture.htb", (self.workspace / "assessor-vhost-input.txt").read_text())
                self.assertNotIn("--dry-run", self.commands("web-assess")[0])
                self.assertLess(result.stdout.index("Web application assessment"),
                                result.stdout.index("8. SMB enumeration"))
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
        for tool in ("ffuf", "feroxbuster", "nikto", "droopescan", "wpscan", "joomscan"):
            self.assertFalse(self.commands(tool), f"{tool} must honor WEB_ENUM=0")
        self.assertEqual(self.commands("nuclei"), [["-update-templates"]])
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

    def test_preflight_failure_preserves_existing_evidence(self):
        evidence = self.workspace / "scans/tcp-services.txt"
        evidence.write_text("Keep previous evidence\n")
        self.env["HTB_PYTHON"] = "missing-python-for-test"
        result = self.call(self.workspace / "recon.sh")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(evidence.read_text(), "Keep previous evidence\n")
        self.assertFalse((self.workspace / "runs").exists())
        self.assertFalse((self.workspace / "recon-console.log").exists())

    def test_failed_service_scan_archives_previous_evidence_and_reports_incomplete(self):
        old = self.workspace / "scans/tcp-services.xml"
        old.write_text("old service evidence must not enter this run\n")
        (self.workspace / "enum/web/old-finding.txt").write_text("OLD_TARGET_ONLY\n")
        (self.workspace / "run-target.env").write_text('IP="192.0.2.99"\n')
        self.env.update(MOCK_NMAP_FAIL="services", MOCK_PORTS="22")
        result = self.recon(expected_status=2)
        self.assertFalse(old.exists())
        self.assertFalse((self.workspace / "enum/web/old-finding.txt").exists())
        archived = list((self.workspace / "runs").iterdir())
        self.assertEqual(len(archived), 1)
        self.assertIn("old service evidence", (archived[0] / "scans/tcp-services.xml").read_text())
        self.assertEqual((archived[0] / ".target.env").read_text(), 'IP="192.0.2.99"\n')
        status = json.loads((self.workspace / "run-status.json").read_text())
        self.assertEqual(status["status"], "incomplete")
        self.assertTrue(any(s["stage"] == 2 and s["status"] == "error" for s in status["stages"]))
        self.assertIn("incomplete", result.stdout.lower())
        self.assertNotIn("OLD_TARGET_ONLY", (self.workspace / "summary.md").read_text())
        self.assertIn("incomplete", (self.workspace / "summary.md").read_text())

    def test_discovery_timeout_continues_udp_enumeration_and_offline_analysis(self):
        self.env.update(MOCK_NMAP_FAIL="discovery", MOCK_UDP="161")
        self.recon(expected_status=2)
        self.assertTrue(self.commands("snmpwalk"))
        analyzer = self.commands("analyzer")
        self.assertEqual(len(analyzer), 1)
        self.assertIn("-I", analyzer[0])
        self.assertEqual(analyzer[0][0], bash_path(sys.executable))
        self.assertNotIn("--online-vuln-check", analyzer[0])
        status = json.loads((self.workspace / "run-status.json").read_text())
        self.assertEqual(status["status"], "incomplete")
        self.assertTrue(any(s["stage"] == 13 and s["status"] == "completed" for s in status["stages"]))
        self.assertTrue(any(s["stage"] == 2 and s["status"] == "skipped" for s in status["stages"]))

    def test_identified_http_service_overrides_conventional_port_filter(self):
        self.env.update(MOCK_PORTS="22", MOCK_SERVICE="http")
        self.recon()
        self.assertIn("http://192.0.2.10:22", (self.workspace / "enum/web/live-web-urls.txt").read_text())
        self.assertTrue(self.commands("curl"))

    def test_external_assets_are_not_fetched_or_redirects_enabled(self):
        self.env["MOCK_HTTP_BODY"] = '<script src="https://outside.example/app.js"></script>'
        self.recon()
        for args in self.commands("curl"):
            self.assertFalse(any("outside.example" in arg for arg in args))
        for args in self.commands("whatweb"):
            self.assertIn("--follow-redirect=never", args)
        status = json.loads((self.workspace / "run-status.json").read_text())
        self.assertTrue(any(c["command"] == "External JavaScript reference excluded from scope"
                            for s in status["stages"] for c in s["commands"]))

    def test_web_session_and_request_files_are_forwarded_without_logging_secrets(self):
        self.mock_assessor()
        session = self.root / "session with spaces.json"
        captures = self.root / "captured requests.json"
        session.write_text('{"secret":"PRIVATE_SESSION_VALUE"}')
        captures.write_text('{"requests":[]}')
        self.env.update(WEB_ASSESS="1", WEB_SESSION_FILE=bash_path(session), WEB_REQUESTS_FILE=bash_path(captures))
        result = self.recon()
        self.assertEqual(self.commands("web-assess"), [["--session-file", bash_path(session), "--requests-file", bash_path(captures)]])
        self.assertNotIn("PRIVATE_SESSION_VALUE", result.stdout)
        self.assertNotIn("PRIVATE_SESSION_VALUE", (self.workspace / "run-status.json").read_text())

    def test_archive_failure_refreshes_overview_as_incomplete(self):
        self.env.update(MOCK_PORTS="22", MOCK_ZIP_EXIT="7")
        self.recon(expected_status=2)
        self.assertEqual(len(self.commands("analyzer")), 2)
        status = json.loads((self.workspace / "run-status.json").read_text())
        self.assertEqual(status["status"], "incomplete")
        self.assertTrue(any(s["stage"] == 24 and s["status"] == "error" for s in status["stages"]))

    def test_windows_services_get_bounded_nse_xml_and_ldaps_uses_actual_port(self):
        self.env.update(MOCK_PORTS="88,445,636,1433,3389,5986", MOCK_HTTP_STATUS="000",
                        MOCK_SERVICE_MAP="88=kerberos-sec,445=microsoft-ds,636=ssl/ldap,1433=ms-sql-s,3389=ms-wbt-server,5986=ssl/wsman")
        self.recon()
        scans = self.commands("nmap")
        expected = {"enum/rdp/nmap-rdp.xml": ("3389", "rdp-ntlm-info,rdp-enum-encryption"),
                    "enum/mssql/nmap-mssql.xml": ("1433", "ms-sql-info,ms-sql-ntlm-info"),
                    "enum/ldap/nmap-ldap.xml": ("636", "ldap-rootdse"),
                    "enum/winrm/nmap-winrm.xml": ("5986", "+http-ntlm-info")}
        for evidence, (port, scripts) in expected.items():
            scan = next(args for args in scans if evidence in args)
            self.assertIn("-sV", scan)
            self.assertEqual(scan[scan.index("-p") + 1], port)
            self.assertEqual(scan[scan.index("--script") + 1], scripts)
            self.assertTrue((self.workspace / evidence).exists())
        mssql = next(args for args in scans if "enum/mssql/nmap-mssql.xml" in args)
        self.assertIn("mssql.scanned-ports-only=true", mssql)
        anonymous = next(args for args in scans if "enum/ldap/nmap-ldap-search.xml" in args)
        self.assertEqual(anonymous[anonymous.index("--script") + 1], "ldap-search")
        self.assertEqual(anonymous[anonymous.index("--script-args") + 1],
                         "ldap.maxobjects=20,ldap.qfilter=users,ldap.attrib=sAMAccountName")
        self.assertEqual(anonymous[anonymous.index("-p") + 1], "636")
        self.assertTrue((self.workspace / "enum/ldap/nmap-ldap-search.xml").exists())
        self.assertTrue((self.workspace / "enum/smb/nmap-smb-445.xml").exists())
        self.assertTrue((self.workspace / "enum/kerberos/nmap-kerberos.xml").exists())
        self.assertFalse(any("krb5-enum-users" in arg for scan in scans for arg in scan))
        ldap = self.commands("ldapsearch")
        self.assertEqual(len(ldap), 1)
        self.assertEqual(ldap[0][ldap[0].index("-H") + 1], "ldaps://192.0.2.10:636")
        self.assertEqual(ldap[0][ldap[0].index("-s") + 1], "base")
        self.assertIn("# Target: ldaps://192.0.2.10:636", (self.workspace / "enum/ldap/namingcontexts-636.txt").read_text())

    def test_identified_windows_services_on_unusual_ports_use_explicit_endpoints(self):
        self.env.update(MOCK_PORTS="2445,2636,21433,23389,25985", MOCK_HTTP_STATUS="000",
                        MOCK_SERVICE_MAP="2445=microsoft-ds,2636=ssl/ldap,21433=ms-sql-s,23389=ms-wbt-server,25985=winrm")
        self.recon()
        scans = self.commands("nmap")
        for evidence, port in (("smb/nmap-smb-2445.xml", "2445"), ("ldap/nmap-ldap.xml", "2636"),
                               ("mssql/nmap-mssql.xml", "21433"), ("rdp/nmap-rdp.xml", "23389"),
                               ("winrm/nmap-winrm.xml", "25985")):
            scan = next(args for args in scans if "enum/" + evidence in args)
            self.assertEqual(scan[scan.index("-p") + 1], port)
        smb = next(args for args in scans if "enum/smb/nmap-smb-2445.xml" in args)
        self.assertIn("smbport=2445", smb)
        self.assertEqual(self.commands("smbclient")[0][-2:], ["-p", "2445"])
        self.assertIn("ldaps://192.0.2.10:2636", self.commands("ldapsearch")[0])
        self.assertFalse(self.commands("netexec"))
        self.assertFalse(self.commands("crackmapexec"))
        self.assertFalse(self.commands("enum4linux-ng"))

    def test_winrm_fingerprint_is_not_a_webapp_but_real_app_on_same_port_is(self):
        self.env.update(MOCK_PORTS="5985", MOCK_SERVICE="http", WEB_ENUM="0")
        for product, is_webapp in (("Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)", False), ("nginx 1.24", True)):
            with self.subTest(product=product):
                self.env["MOCK_PRODUCT"] = product
                self.recon()
                urls = (self.workspace / "enum/web/live-web-urls.txt").read_text()
                self.assertEqual("http://192.0.2.10:5985" in urls, is_webapp)

    def test_smb_netbios_only_retains_139_without_default_445_clients(self):
        self.env.update(MOCK_PORTS="139", MOCK_SERVICE="netbios-ssn", MOCK_HTTP_STATUS="000")
        self.recon()
        self.assertEqual(self.commands("smbclient")[0][-2:], ["-p", "139"])
        smb = next(args for args in self.commands("nmap") if "enum/smb/nmap-smb-139.xml" in args)
        self.assertEqual(smb[smb.index("-p") + 1], "139")
        self.assertFalse(any(arg.startswith("smbport=") for arg in smb))
        self.assertTrue(self.commands("enum4linux-ng"))
        for tool in ("smbmap", "netexec", "crackmapexec"):
            self.assertFalse(self.commands(tool), tool)
        status = json.loads((self.workspace / "run-status.json").read_text())
        self.assertTrue(any(c["status"] == "skipped" and "445 not discovered" in c["command"]
                            for s in status["stages"] for c in s["commands"]))

    def test_rdp_timeout_marks_incomplete_and_still_collects_mssql(self):
        self.env.update(MOCK_PORTS="1433,3389", MOCK_HTTP_STATUS="000",
                        MOCK_SERVICE_MAP="1433=ms-sql-s,3389=ms-wbt-server",
                        MOCK_NMAP_FAIL_OUTPUT="enum/rdp/nmap-rdp.txt")
        self.recon(expected_status=2)
        self.assertTrue((self.workspace / "enum/mssql/nmap-mssql.xml").exists())
        self.assertTrue(self.commands("analyzer"))
        status = json.loads((self.workspace / "run-status.json").read_text())
        self.assertTrue(any(s["stage"] == 17 and s["status"] == "error" for s in status["stages"]))

    def test_absent_windows_services_and_unconfirmed_snmp_are_explicitly_skipped(self):
        self.env.update(MOCK_PORTS="22", MOCK_HTTP_STATUS="000", MOCK_UDP="161", MOCK_UDP_STATE="open|filtered")
        self.recon()
        self.assertFalse(self.commands("snmpwalk"))
        self.assertFalse(self.commands("onesixtyone"))
        status = json.loads((self.workspace / "run-status.json").read_text())
        for number in (8, 13, 14, 15, 16, 17, 18):
            self.assertTrue(any(s["stage"] == number and s["status"] == "skipped" for s in status["stages"]), number)

    def test_local_archive_is_private_and_preserves_raw_evidence(self):
        result = self.call(self.workspace / "zip-recon.sh")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.commands("zip-umask"), [["0077"]])
        self.assertIn("enum/", self.commands("zip")[0])
        self.assertNotIn("*.jsonl", self.commands("zip")[0])
        self.assertIn("may contain session credentials", result.stdout)
        archive = next(self.workspace.glob("*.zip"))
        if os.name != "nt":
            self.assertEqual(archive.stat().st_mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
