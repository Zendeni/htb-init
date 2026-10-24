"""Regression checks for the standalone analyzer; all network calls are mocked."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("htb_legacy_analyzer", ROOT / "analyze-recon.py")
analyzer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = analyzer
SPEC.loader.exec_module(analyzer)


class LegacyAnalyzerTests(unittest.TestCase):
    def data(self, files=None):
        data = analyzer.ReconData(root=ROOT, source=ROOT)
        data.files = files or {}
        return data

    def test_tcp_and_udp_with_same_port_are_both_reported(self):
        data = self.data({
            "scans/tcp-services.txt": "53/tcp open domain TCP DNS banner\n",
            "scans/udp-top100.txt": "53/udp open domain UDP DNS banner\n",
        })
        analyzer.parse_ports(data)
        self.assertEqual(set(data.ports), {(53, "tcp"), (53, "udp")})
        self.assertEqual(data.ports[(53, "tcp")].version, "TCP DNS banner")
        self.assertEqual(data.ports[(53, "udp")].version, "UDP DNS banner")
        report = analyzer.render_report(data, analyzer.build_findings(data))
        self.assertIn("TCP DNS banner", report)
        self.assertIn("UDP DNS banner", report)

    def test_protocol_aware_table_does_not_create_phantom_tcp_service(self):
        data = self.data({"scans/port-summary.md": "| 161 | udp | snmp | SNMPv2 |\n"})
        analyzer.parse_ports(data)
        self.assertEqual(set(data.ports), {(161, "udp")})
        self.assertEqual(data.ports[(161, "udp")].service, "snmp")

    def test_legacy_table_and_richer_banner_still_combine(self):
        data = self.data({
            "scans/port-summary.md": "| 22 | ssh | |\n",
            "scans/tcp-services.txt": "22/tcp open ssh OpenSSH 9.9\n",
        })
        analyzer.parse_ports(data)
        self.assertEqual(data.ports[(22, "tcp")].version, "OpenSSH 9.9")
        self.assertTrue(any(f.title == "SSH exposed" for f in analyzer.build_findings(data)))

    def test_udp_does_not_trigger_tcp_technology_or_web_assumptions(self):
        data = self.data()
        for port in (22, 443, 8080, 10050):
            analyzer.add_port(data, port, "unknown", proto="udp")
        analyzer.infer_tech_from_ports(data)
        analyzer.normalize_web_ports(data)
        self.assertFalse(data.technologies)
        self.assertNotIn("Web application", analyzer.detect_profile(data))
        self.assertEqual(analyzer.preferred_web_base(data), "http://<target>")
        self.assertFalse(any(f.title == "SSH exposed" for f in analyzer.build_findings(data)))

    def test_udp_dns_remains_visible_in_findings(self):
        data = self.data()
        analyzer.add_port(data, 53, "domain", proto="udp")
        self.assertTrue(any(f.title == "DNS service exposed" for f in analyzer.build_findings(data)))

    def test_open_filtered_is_not_confirmed_open(self):
        data = self.data({"scans/udp-top100.txt": "161/udp open|filtered snmp\n"})
        analyzer.parse_ports(data)
        self.assertFalse(data.ports)

    def test_crlf_nmap_lines_with_and_without_banner_are_parsed(self):
        data = self.data({"scans/tcp-services.txt":
            "22/tcp open ssh OpenSSH 9.9\r\n80/tcp open http\r\n"})
        analyzer.parse_ports(data)
        self.assertEqual(set(data.ports), {(22, "tcp"), (80, "tcp")})
        self.assertEqual(data.ports[(22, "tcp")].version, "OpenSSH 9.9")

    def test_npm_ranges_are_not_treated_as_exact_versions(self):
        data = self.data({"loot/package.json": json.dumps({"dependencies": {
            "caret": "^15.0.0", "tilde": "~15.0.0", "minimum": ">=4.0.0 <4.18.0",
            "wildcard": "15.x", "partial": "15.0", "tag": "latest",
            "exact": "15.1.2", "preview": "v19.0.0-rc.1+build.2",
        }})})
        analyzer.parse_package_files(data)
        self.assertEqual(dict(data.package_versions), {
            "npm:exact": {"15.1.2"}, "npm:preview": {"19.0.0-rc.1+build.2"},
        })

    def test_lockfile_still_supplies_exact_version_for_manifest_range(self):
        data = self.data({
            "loot/package.json": json.dumps({"dependencies": {"next": "^15.0.0"}}),
            "loot/package-lock.json": json.dumps({"packages": {
                "node_modules/next": {"version": "15.2.4"},
            }}),
        })
        analyzer.parse_package_files(data)
        self.assertEqual(data.package_versions["npm:next"], {"15.2.4"})

    def test_nested_and_scoped_lockfile_paths_use_registry_package_names(self):
        data = self.data({"loot/package-lock.json": json.dumps({"packages": {
            "node_modules/parent": {"version": "1.0.0"},
            "node_modules/parent/node_modules/child": {"version": "2.0.0"},
            "node_modules/parent/node_modules/@scope/child": {"version": "3.0.0"},
            "packages/workspace/node_modules/child": {"version": "2.1.0"},
        }})})
        analyzer.parse_package_files(data)
        self.assertEqual(dict(data.package_versions), {
            "npm:parent": {"1.0.0"}, "npm:child": {"2.0.0", "2.1.0"},
            "npm:@scope/child": {"3.0.0"},
        })
        with patch.object(analyzer, "http_json", return_value={"results": []}) as request, \
                patch.object(analyzer.time, "sleep"):
            analyzer.run_osv_lookup(data, {})
        queries = request.call_args.args[2]["queries"]
        self.assertEqual({q["package"]["name"] for q in queries}, {"parent", "child", "@scope/child"})

    def test_non_object_json_packages_do_not_abort_report(self):
        for filename in ("package.json", "package-lock.json", "npm-shrinkwrap.json", "composer.lock"):
            for value in ([], None, "unexpected", 123):
                with self.subTest(filename=filename, value=value):
                    data = self.data({f"loot/{filename}": json.dumps(value)})
                    analyzer.parse_package_files(data)
                    self.assertFalse(data.package_versions)

    def test_osv_receives_only_real_package_ecosystems(self):
        data = self.data()
        analyzer.add_package(data, "generic", "zabbix", "6.0.0")
        analyzer.add_package(data, "npm", "next", "15.0.0")
        with patch.object(analyzer, "http_json", return_value={"results": [{}]}) as request, \
                patch.object(analyzer.time, "sleep"):
            analyzer.run_osv_lookup(data, {})
        self.assertEqual(request.call_args.args[2], {"queries": [
            {"package": {"ecosystem": "npm", "name": "next"}, "version": "15.0.0"},
        ]})
        self.assertIn("zabbix 6.0.0", analyzer.nvd_keyword_terms(data))

    def test_generic_only_inventory_does_not_call_osv(self):
        data = self.data()
        analyzer.add_package(data, "generic", "zabbix", "6.0.0")
        with patch.object(analyzer, "http_json") as request:
            self.assertEqual(analyzer.run_osv_lookup(data, {}), [])
        request.assert_not_called()

    def test_complete_offline_report_with_mixed_transports_and_bad_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scans").mkdir()
            (root / "loot").mkdir()
            (root / "scans" / "tcp-services.txt").write_text("53/tcp open domain DNS TCP\n")
            (root / "scans" / "udp-top100.txt").write_text("53/udp open domain DNS UDP\n")
            (root / "loot" / "package.json").write_text("[]")
            data = analyzer.load_recon(root, root)
            with patch.object(analyzer, "http_json") as request:
                analyzer.run_vulnerability_intel(data, False, root / "cache.json", 1, "", 8)
            request.assert_not_called()
            report = analyzer.render_report(data, analyzer.build_findings(data))
            self.assertIn("DNS TCP", report)
            self.assertIn("DNS UDP", report)

    def test_scanner_inventory_and_probe_names_are_not_target_evidence(self):
        data = self.data({
            "enum/web/live-web-urls.txt": "http://192.0.2.10:80\n",
            "enum/web/curl-web-probe.txt": "http://192.0.2.10:1883 000\n",
            "summary.md": "http://192.0.2.10:5985\nZabbix JWT JWKS Grafana Jenkins\n",
            "enum/web/jwks.json-http___192_0_2_10_80.txt": "HTTP/1.1 404\n",
            "enum/web/assessments/run/http.templates.txt": (
                "http/default-logins/zabbix/zabbix-default-login.yaml\n"
                "http/exposures/tokens/generic/jwt-token.yaml\n"
            ),
            "enum/web/assessments/run/report.json": json.dumps({
                "status": "incomplete", "findings": [], "diagnostics": ["timed out"],
            }),
        })
        data.ip = "192.0.2.10"
        data.scope_include = [data.ip]
        analyzer.parse_web(data)
        analyzer.parse_web_assessment(data)
        self.assertEqual(data.web_urls, {"http://192.0.2.10:80"})
        self.assertFalse({"Zabbix", "JWT", "JWKS", "Grafana", "Jenkins"} & data.technologies)
        self.assertEqual(data.assessment_status, "incomplete")
        self.assertFalse(data.scanner_matches)

    def test_mqtt_smb_and_ad_profile_become_prioritized_evidence(self):
        mqtt = (
            "1883/tcp open mqtt\n| mqtt-subscribe:\n"
            '| $SYS/brokers/client_status/mqttui-test: {"username":"(null)",'
            '"client_id":"mqttui-test","IPv4":"127.0.0.1"}\n'
        )
        data = self.data({
            "scans/tcp-services.txt": mqtt + "445/tcp open microsoft-ds\n",
            "scans/target-profile.txt": (
                "profile=windows-ad-dc\ndomain=example.htb\nrealm=EXAMPLE.HTB\n"
                "dc_hostname=dc01.example.htb\nclock_skew=7h58m30s\n"
            ),
            "enum/ad/ntp-query.txt": "now +28711.39 +/- 0.05 192.0.2.10\n",
            "enum/smb/netexec-smb.txt": (
                "SMB 192.0.2.10 445 DC01 (name:DC01) (domain:example.htb) "
                "(signing:True) (Null Auth:True)\n"
            ),
            "enum/smb/enum4linux.txt": (
                "Domain Sid: S-1-5-21-1-2-3\nNT_STATUS_ACCESS_DENIED\n"
            ),
        })
        analyzer.parse_ports(data)
        analyzer.parse_smb(data)
        analyzer.parse_target_profile(data)
        analyzer.parse_mqtt(data)
        findings = analyzer.build_findings(data)
        self.assertEqual(findings[0].title, "Anonymous MQTT read access confirmed")
        self.assertEqual(findings[1].title, "Kerberos clock skew requires attention")
        self.assertEqual(findings[2].title, "Restricted SMB null session")
        self.assertTrue(data.smb_signing_required)
        self.assertEqual(data.domain_sid, "S-1-5-21-1-2-3")
        report = analyzer.render_report(data, findings)
        self.assertIn("MQTT Intelligence", report)
        self.assertIn("SMB signing: `required`", report)
        self.assertIn("EXAMPLE.HTB", report)

    def test_history_and_template_inventory_are_not_loaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scans").mkdir()
            (root / "enum" / "web" / "assessments" / "run").mkdir(parents=True)
            (root / ".recon-history" / "old" / "enum").mkdir(parents=True)
            (root / "scans" / "tcp-services.txt").write_text("80/tcp open http IIS\n")
            (root / "enum" / "web" / "assessments" / "run" / "http.templates.txt").write_text("Zabbix\n")
            (root / ".recon-history" / "old" / "enum" / "stale.txt").write_text("JWT\n")
            data = analyzer.load_recon(root, root)
            self.assertNotIn("enum/web/assessments/run/http.templates.txt", data.files)
            self.assertFalse(any(path.startswith(".recon-history/") for path in data.files))


if __name__ == "__main__":
    unittest.main()
