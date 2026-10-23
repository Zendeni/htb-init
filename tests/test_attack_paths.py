"""Offline evidence/ranking regressions. No live targets or vulnerability APIs."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("htb_attack_paths", ROOT / "analyze-recon.py")
analyzer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = analyzer
SPEC.loader.exec_module(analyzer)


def finding(template="reflected-xss", target="https://app.test/search?q=secret", severity="medium"):
    return {"template-id": template, "matched-at": target, "matcher-status": True,
            "info": {"name": template, "severity": severity}}


class AttackPathTests(unittest.TestCase):
    def load(self, files=None):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        inputs = {".target.env": 'IP="10.10.10.1"\nHOST="app.test"\n',
                  "run-status.json": json.dumps({"status": "completed", "stages": []})}
        inputs.update(files or {})
        for rel, content in inputs.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        data = analyzer.load_recon(root, root)
        analyzer.run_vulnerability_intel(data, False, root / "cache.json", 1, "", 8)
        return data

    def assessment(self, rows=(), run="20261023-120000-a", status="completed"):
        prefix = f"enum/web/assessments/{run}/"
        return {prefix + "report.json": json.dumps({"status": status, "stages": [], "oast_enabled": False}),
                prefix + "http.jsonl": "\n".join(json.dumps(row) for row in rows)}

    def test_inventory_logs_and_generated_reports_cannot_invent_products(self):
        files = self.assessment()
        prefix = "enum/web/assessments/20261023-120000-a/"
        poison = "Zabbix Server 6.0.27 Grafana Jenkins CVE-2024-22120 Next.js 13.0.0 appDir:!0"
        files.update({prefix + "http.templates.txt": poison, prefix + "report.md": poison,
                      prefix + "http.log": poison, "summary.md": poison,
                      "enum/web/headers.txt": "Server: nginx/1.24.0\n"})
        data = self.load(files)
        self.assertFalse(any("zabbix" in value.lower() or "grafana" in value.lower() or "jenkins" in value.lower() for value in data.technologies))
        self.assertFalse(data.nextjs_versions)
        self.assertEqual(analyzer.build_overview(data)["routes"], [])

    def test_scanner_evidence_outranks_critical_keyword_advisory(self):
        data = self.load(self.assessment([finding()]))
        data.vuln_matches.append(analyzer.VulnMatch("NVD", "CVE-2099-1", title="Remote code execution", severity="CRITICAL", package="unknown"))
        self.assertEqual(analyzer.top_vuln_candidates(data)[0].vuln_id, "reflected-xss")
        route = analyzer.build_overview(data)["routes"][0]
        self.assertEqual(route["target"], "https://app.test/search?q")
        self.assertEqual(route["evidence"][0]["line"], 1)
        self.assertEqual(len(route["evidence"][0]["sha256"]), 64)
        self.assertNotIn("secret", json.dumps(analyzer.build_overview(data)))

    def test_empty_and_info_only_runs_do_not_create_routes(self):
        for rows in ([], [finding("nginx-version", severity="info")], [dict(finding(), **{"matcher-status": False})]):
            with self.subTest(rows=rows):
                self.assertEqual(analyzer.build_overview(self.load(self.assessment(rows)))["routes"], [])

    def test_newer_empty_run_suppresses_old_hits_and_archives(self):
        files = self.assessment([finding()], run="20261022-120000-a")
        files.update(self.assessment([], run="20261023-120000-b"))
        files["runs/old/scans/tcp-services.txt"] = "10051/tcp open zabbix Zabbix Server 6.0.27\n"
        files["runs/old/enum/web/package.json"] = '{"dependencies":{"next":"13.0.0"}}'
        data = self.load(files)
        self.assertEqual(data.vuln_matches, [])
        self.assertFalse(data.ports)
        self.assertFalse(data.package_versions)

    def test_explicit_latest_pointer_handles_same_second_runs(self):
        files = self.assessment([finding()], run="20261023-120000-z")
        files.update(self.assessment([], run="20261023-120000-a"))
        files["enum/web/assessments/latest.json"] = '{"run_id":"20261023-120000-a"}'
        self.assertEqual(self.load(files).vuln_matches, [])
        files["enum/web/assessments/latest.json"] = '{"run_id":"missing"}'
        data = self.load(files)
        self.assertEqual(data.vuln_matches, [])
        self.assertTrue(any("pointer" in note for note in data.coverage))

    def test_report_only_findings_keep_json_locator_and_aliases(self):
        item = finding()
        item["info"]["classification"] = {"cve-id": ["CVE-2024-12345"]}
        data = self.load({"enum/web/assessments/20261023-120000-a/report.json": json.dumps({"status": "completed", "findings": [item]})})
        match = data.vuln_matches[0]
        self.assertEqual(match.evidence[0]["locator"], "findings[0]")
        self.assertEqual(match.aliases, ["CVE-2024-12345"])

    def test_scope_exclusions_and_external_links_do_not_redirect_routes(self):
        files = self.assessment([finding(target="https://outside.test/admin")])
        files.update({"enum/web/live-web-urls.txt": "https://app.test/\n", "enum/web/page.html": '<a href="http://docs.vendor.test/guide">help</a>'})
        data = self.load(files)
        self.assertEqual(analyzer.preferred_web_base(data), "https://app.test")
        self.assertEqual(analyzer.build_overview(data)["routes"], [])
        files["scope.json"] = '{"include":["app.test"],"exclude":["app.test"]}'
        files.update(self.assessment([finding()]))
        self.assertEqual(self.load(files).vuln_matches, [])

    def test_same_template_at_two_apps_retains_two_attributions(self):
        files = self.assessment([finding(target="https://app.test/a"), finding(target="https://second.test/b")])
        files["scope.json"] = '{"include":["app.test","second.test"],"exclude":[]}'
        routes = analyzer.build_overview(self.load(files))["routes"]
        self.assertEqual({row["target"] for row in routes}, {"https://app.test/a", "https://second.test/b"})

    def test_same_family_groups_inputs_but_keeps_method_parameter_and_session(self):
        rows = []
        for endpoint in ("/api/json", "/api/xml", "/submit"):
            item = finding("sqli-error", target="https://app.test" + endpoint, severity="high")
            item.update({"fuzzing_method": "POST", "fuzzing_parameter": "q", "fuzzing_position": "body",
                         "request": "POST / HTTP/1.1\r\nAuthorization: secret-session\r\n\r\nsecret-body"})
            rows.append(item)
        rows.append(finding())
        overview = analyzer.build_overview(self.load(self.assessment(rows)))
        self.assertEqual(len(overview["routes"]), 2)
        route = overview["routes"][0]
        self.assertEqual(len(route["inputs"]), 3)
        self.assertEqual(route["inputs"][0]["method"], "POST")
        self.assertEqual(route["inputs"][0]["parameter"], "q")
        self.assertTrue(route["inputs"][0]["session_present"])
        self.assertIn("Replay POST /api/json body field q", route["next_test"])
        self.assertIn("+2 other inputs", analyzer.render_overview(overview))
        self.assertNotIn("secret-session", json.dumps(overview))
        self.assertNotIn("secret-body", json.dumps(overview))

    def test_osv_response_versions_stay_attached_to_their_origin(self):
        data = self.load({"scope.json": '{"include":["app.test","second.test"],"exclude":[]}',
                          "enum/web/live-web-urls.txt": "https://app.test/\nhttps://second.test/\n",
                          "enum/web/a.js": 'URL: https://app.test/a.js\nwindow.next={version:"13.0.0",appDir:!1};',
                          "enum/web/b.js": 'URL: https://second.test/b.js\nwindow.next={version:"16.0.0",appDir:!0};'})
        response = {"results": [{"vulns": [{"id": "GHSA-test-test-test", "summary": "Next affected", "severity": [{"score": "HIGH"}], "references": [{"url": "https://example.test/advisory"}]}]}]}
        queries = [{"package": {"ecosystem": "npm", "name": "next"}, "version": "13.0.0"}]
        with patch.object(analyzer, "http_json", side_effect=AssertionError("network forbidden")):
            data.vuln_matches = analyzer.extract_osv_matches(data, response, queries, {})
        routes = analyzer.build_overview(data)["routes"]
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0]["target"], "https://app.test")
        self.assertEqual(routes[0]["evidence"][0]["path"], "enum/web/a.js")

    def test_unattributed_bundle_is_not_assigned_across_apps(self):
        data = self.load({"scope.json": '{"include":["app.test","second.test"],"exclude":[]}',
                          "enum/web/live-web-urls.txt": "https://app.test/\nhttps://second.test/\n",
                          "enum/web/bundle.js": 'window.next={version:"13.0.0",appDir:!1};'})
        rows = data.package_evidence["npm:next"]
        self.assertTrue(rows)
        self.assertTrue(all(not row["target"] for row in rows))
        self.assertFalse(data.nextjs_app_router)

    def test_unrelated_rce_and_middleware_advisories_do_not_become_next_routes(self):
        data = self.load({"enum/web/page.html": 'window.next={version:"16.0.0",appDir:!0};'})
        data.vuln_matches = [analyzer.VulnMatch("OSV", "other", title="OpenSSH remote code execution", package="openssh", ecosystem="Debian"),
                             analyzer.VulnMatch("NVD", "other2", title="Django middleware bypass", severity="CRITICAL")]
        findings = analyzer.build_findings(data)
        self.assertFalse(any("middleware authorization" in row.title for row in findings))
        self.assertFalse(any(row.confidence == "high" and "Next.js" in row.title for row in findings))
        self.assertEqual(analyzer.build_overview(data)["routes"], [])

    def test_zabbix_requires_server_affected_version_and_account_prerequisite(self):
        for banner in ("Zabbix Agent 6.0.27", "Zabbix Frontend 6.0.27", "Zabbix Server 6.0.28", "Zabbix Server 6.4.13", "Zabbix Server 7.0.0beta2", "Zabbix Server 7.0.0"):
            with self.subTest(banner=banner):
                data = self.load({"scans/tcp-services.txt": f"10051/tcp open zabbix {banner}\n"})
                self.assertEqual(data.vuln_matches, [])
        data = self.load({"scans/tcp-services.txt": "10051/tcp open zabbix Zabbix Server 6.0.27\n"})
        route = analyzer.build_overview(data)["routes"][0]
        self.assertEqual(route["advisory_ids"], ["CVE-2024-22120"])
        self.assertIn("low-privilege", route["prerequisites"][0])
        self.assertEqual(route["status"], "advisory-candidate")

    def test_nse_text_vulnerable_and_vulners_have_different_status(self):
        text = "Nmap scan report for app.test (10.10.10.1)\n80/tcp open http\n| http-vuln-test:\n|   VULNERABLE:\n|   Risk factor: HIGH\n|   IDs: CVE:CVE-2024-12345\n|_  details\n| vulners:\n|_  CVE-2024-99999 9.8\n"
        data = self.load({"scans/tcp-services.txt": text})
        self.assertEqual(len(data.vuln_matches), 2)
        matches = {m.vuln_id: m for m in data.vuln_matches}
        self.assertEqual(matches["http-vuln-test"].status, "scanner-match")
        self.assertEqual(matches["vulners"].status, "advisory-candidate")
        self.assertEqual(len(analyzer.build_overview(data)["routes"]), 1)
        self.assertEqual(matches["http-vuln-test"].target, "tcp://10.10.10.1:80")

    def test_nse_xml_keeps_scope_and_script_locator(self):
        xml = '<nmaprun><host><address addr="10.10.10.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><script id="http-vuln-test" output="VULNERABLE:&#10;CVE-2024-12345"/></port></ports></host></nmaprun>'
        data = self.load({"scans/tcp-services.xml": xml})
        self.assertEqual(len(analyzer.build_overview(data)["routes"]), 1)
        self.assertIn("port[443]", data.vuln_matches[0].evidence[0]["locator"])

    def test_cvss_vectors_numeric_and_unknown_versions(self):
        critical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        self.assertEqual(analyzer.cvss_score(critical), 9.8)
        self.assertEqual(analyzer.severity_rank(critical), 0)
        self.assertEqual(analyzer.severity_rank("9.8"), 0)
        self.assertEqual(analyzer.severity_rank("CVSS:4.0/AV:N"), 4)
        self.assertEqual(analyzer.severity_rank("CVSS:3.1/AV:N"), 4)
        data = self.load()
        match = analyzer.score_vuln_match(data, analyzer.VulnMatch("NVD", "CVE-1", title="source information disclosure", severity=critical))
        self.assertNotIn("RCE/code execution", match.reason)
        data.vuln_matches = [match]
        self.assertEqual(analyzer.build_overview(data)["routes"], [])

    def test_peer_and_dev_or_wildcard_requirements_cannot_claim_deployment(self):
        data = self.load({"loot/requirements.txt": "Django==4.2.*\nFlask==3.0.0\n",
                          "loot/package.json": '{"peerDependencies":{"next":"13.0.0"},"devDependencies":{"jest":"29.0.0"}}'})
        self.assertNotIn("PyPI:Django", data.package_versions)
        self.assertNotIn("npm:next", data.package_versions)
        self.assertEqual(data.package_evidence["npm:jest"][0]["kind"], "dev-declared")
        self.assertFalse(data.package_evidence["npm:jest"][0]["target"])

    def test_cache_expiry_and_query_parameters(self):
        cache = {}
        with patch.object(analyzer.time, "time", return_value=1000):
            analyzer.cache_response(cache, "key", {"value": 1})
            self.assertEqual(analyzer.cached_response(cache, "key"), {"value": 1})
        with patch.object(analyzer.time, "time", return_value=1000 + analyzer.CACHE_TTL_SECONDS + 1):
            self.assertIsNone(analyzer.cached_response(cache, "key"))
        self.assertIsNone(analyzer.cached_response({"key": {"legacy": True}}, "key"))
        data = self.load()
        with patch.object(analyzer, "nvd_keyword_terms", return_value=["nginx"]), patch.object(analyzer, "http_json", return_value={"vulnerabilities": []}) as query, patch.object(analyzer.time, "sleep"):
            analyzer.run_nvd_lookup(data, cache, max_results=2)
            analyzer.run_nvd_lookup(data, cache, max_results=8)
            self.assertEqual(query.call_count, 2)

    def test_overview_is_short_and_reflects_failed_collection(self):
        files = self.assessment([finding("a"), finding("b"), finding("c")])
        files["run-status.json"] = json.dumps({"status": "incomplete", "stages": [{"stage": 2, "name": "tcp-services", "status": "error"}]})
        overview = analyzer.build_overview(self.load(files))
        self.assertEqual(overview["status"], "partial")
        self.assertTrue(any("tcp-services" in note for note in overview["coverage"]))
        self.assertLessEqual(len(analyzer.render_overview(overview).split()), 250)


if __name__ == "__main__":
    unittest.main()
