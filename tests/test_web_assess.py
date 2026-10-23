"""Offline regression coverage for web-assess; never scan external services."""
import contextlib
import importlib.util
import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "web-assess.py"
SPEC = importlib.util.spec_from_file_location("web_assess_test_subject", SCRIPT)
WEB_ASSESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WEB_ASSESS)


class WebAssessmentCLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp.name) / "workspace with spaces"
        self.workspace.mkdir()
        (self.workspace / ".target.env").write_text(
            'BOX="example"\nIP="192.0.2.10"\nHOST="example.test"\n',
            encoding="utf-8",
        )
        self.web = self.workspace / "enum" / "web"
        self.web.mkdir(parents=True)
        self.templates = Path(self.temp.name) / "templates with spaces"
        self.templates.mkdir()
        (self.templates / "offline-fixture.yaml").write_text(
            "id: offline-fixture\ninfo:\n  name: Offline fixture\n"
            "  author: regression-test\n  severity: info\n"
            "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/'\n",
            encoding="utf-8",
        )
        (self.templates / "http").mkdir()
        (self.templates / "dast").mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def call(self, *args, dry_run=True):
        command = [
            sys.executable, "-I", str(SCRIPT),
            "--workspace", str(self.workspace),
            "--templates", str(self.templates),
        ]
        if dry_run:
            command.append("--dry-run")
        command.extend(map(str, args))
        return subprocess.run(
            command, text=True, encoding="utf-8", capture_output=True,
            timeout=30, cwd=self.temp.name,
        )

    def reports(self):
        return sorted(self.web.glob("assessments/*/report.json"), key=lambda p: p.stat().st_mtime_ns)

    def latest_report(self):
        paths = self.reports()
        self.assertTrue(paths, "A report should explain what was assessed")
        return json.loads(paths[-1].read_text(encoding="utf-8"))

    def scope(self, include=None, exclude=None):
        (self.workspace / "scope.json").write_text(
            json.dumps({"include": include or [], "exclude": exclude or []}),
            encoding="utf-8",
        )

    def test_help_works_without_workspace_or_scanner(self):
        result = subprocess.run(
            [sys.executable, "-I", str(SCRIPT), "--help"], text=True,
            encoding="utf-8", capture_output=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for option in ("--dry-run", "--no-dast", "--allow-host", "--oast"):
            self.assertIn(option, result.stdout)

    def test_template_path_environment_override(self):
        override = Path(self.temp.name) / "trusted templates"
        with mock.patch.dict(os.environ, {"NUCLEI_TEMPLATES": str(override)}):
            options = WEB_ASSESS.arguments([])
        self.assertEqual(options.templates, override)

    def test_dry_run_preserves_path_and_query_and_removes_fragment(self):
        url = "https://example.test:8443/a%20b/search?q=one&next=%2Fadmin#section"
        result = self.call("--url", url)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = self.latest_report()
        self.assertIn(url.split("#", 1)[0], report["targets"])
        self.assertNotIn(url, report["targets"])

    def test_literal_target_ip_and_hostname_are_in_scope(self):
        result = self.call(
            "--url", "http://192.0.2.10:8080/", "--url", "https://example.test/",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            set(self.latest_report()["targets"]),
            {"http://192.0.2.10:8080/", "https://example.test/"},
        )

    def test_explicit_target_outside_scope_is_rejected(self):
        result = self.call("--url", "https://outside.test/")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("scope", " ".join(self.latest_report()["diagnostics"]).lower())

    def test_discovered_urls_are_deduplicated_and_outside_scope_skipped(self):
        (self.web / "live-web-urls.txt").write_text(
            "http://192.0.2.10:8080/\nhttps://outside.test/\n",
            encoding="utf-8",
        )
        (self.web / "discovered-host-web-urls.txt").write_text(
            "http://192.0.2.10:8080/\nhttps://example.test/login\n",
            encoding="utf-8",
        )
        result = self.call()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = self.latest_report()
        self.assertCountEqual(
            report["targets"],
            ["http://192.0.2.10:8080/", "https://example.test/login"],
        )
        self.assertIn("outside.test", json.dumps(report) + result.stderr + result.stdout)

    def test_urls_file_works_outside_workspace(self):
        urls = Path(self.temp.name) / "manual target urls.txt"
        urls.write_text("https://example.test/one?a=1&b=2\n", encoding="utf-8")
        result = self.call("--urls-file", urls)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("https://example.test/one?a=1&b=2", self.latest_report()["targets"])

    def test_allow_host_is_explicit_and_does_not_imply_subdomains(self):
        allowed = self.call("--allow-host", "other.test", "--url", "https://other.test/")
        self.assertEqual(allowed.returncode, 0, allowed.stderr)
        denied = self.call("--allow-host", "other.test", "--url", "https://sub.other.test/")
        self.assertEqual(denied.returncode, 2, denied.stdout + denied.stderr)

    def test_scope_exclusion_wins_over_metadata_and_allow_host(self):
        self.scope(include=["example.test"], exclude=["example.test"])
        result = self.call("--allow-host", "example.test", "--url", "https://example.test/")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_scope_can_include_additional_hostname(self):
        self.scope(include=["extra.test"])
        result = self.call("--url", "https://extra.test/")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_targets_is_an_error(self):
        result = self.call()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_missing_urls_file_is_an_error(self):
        result = self.call("--urls-file", Path(self.temp.name) / "missing.txt")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_invalid_scope_file_does_not_silently_expand_scope(self):
        for contents in ("{broken json", '{"include": "example.test"}', '{"exclude": 5}'):
            with self.subTest(contents=contents):
                (self.workspace / "scope.json").write_text(contents, encoding="utf-8")
                result = self.call("--url", "https://example.test/")
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_empty_scope_cannot_authorize_arbitrary_url(self):
        (self.workspace / ".target.env").unlink()
        result = self.call("--url", "https://example.test/")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_invalid_urls_fail_before_any_scanning(self):
        invalid = (
            "https://user:password@example.test/",
            "https://example.test:65536/",
            "https://example.test:notaport/",
            "https://example.test:0/",
            "https://example.test/path\nother",
            "https://example.test/path\tother",
            "file:///etc/passwd",
            "//example.test/path",
        )
        for url in invalid:
            with self.subTest(url=url):
                result = self.call("--url", url)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_invalid_rate_or_timeout_is_rejected(self):
        for option in ("--rate-limit", "--scan-timeout"):
            for value in ("0", "-1", "not-a-number"):
                with self.subTest(option=option, value=value):
                    result = self.call("--url", "https://example.test/", option, value)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_repeated_runs_create_separate_json_and_markdown_reports(self):
        for _ in range(2):
            result = self.call("--url", "https://example.test/")
            self.assertEqual(result.returncode, 0, result.stderr)
        paths = self.reports()
        self.assertEqual(len(paths), 2)
        self.assertNotEqual(paths[0].parent, paths[1].parent)
        for path in paths:
            self.assertTrue(path.with_suffix(".md").is_file())

    def test_environment_file_is_parsed_without_execution(self):
        marker = Path(self.temp.name) / "executed"
        with (self.workspace / ".target.env").open("a", encoding="utf-8") as stream:
            stream.write(f'IGNORED="$(touch {marker.as_posix()})"\n')
        result = self.call("--url", "https://example.test/")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())

    def active(self, *args, inventory="fixture.yaml\n", records="", scan_code=0,
               inventory_code=0, exception=None, installed=True, crawl_info=None):
        """Run the actual orchestration with a fake executable and no networking."""
        calls = []

        def fake_run(command, **kwargs):
            calls.append((list(command), kwargs))
            if "-tl" in command:
                kwargs["stdout"].write(inventory)
                return subprocess.CompletedProcess(command, inventory_code)
            if exception:
                raise exception
            Path(command[command.index("-o") + 1]).write_text(records, encoding="utf-8")
            return subprocess.CompletedProcess(command, scan_code)

        argv = ["--workspace", str(self.workspace), "--templates", str(self.templates),
                "--url", "https://example.test/search?a=1&b=2", *map(str, args)]
        if crawl_info is None:
            argv.append("--no-crawl")
        with mock.patch.object(WEB_ASSESS.shutil, "which", return_value="fake-nuclei" if installed else None), \
                mock.patch.object(WEB_ASSESS.subprocess, "run", side_effect=fake_run), \
                mock.patch.object(WEB_ASSESS, "preflight", return_value=[{"origin": "https://example.test", "reachable": True, "status": 200}]), \
                mock.patch.object(WEB_ASSESS, "crawl", return_value=(["https://example.test/search?a=1&b=2"], crawl_info)), \
                mock.patch.object(WEB_ASSESS.urllib.request, "build_opener", side_effect=AssertionError("Network access is forbidden")), \
                contextlib.redirect_stdout(io.StringIO()):
            code = WEB_ASSESS.main(argv)
        return code, self.latest_report(), calls

    def test_active_empty_results_are_completed_with_real_template_coverage(self):
        code, report, calls = self.active()
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["findings"], [])
        self.assertEqual({s["name"] for s in report["stages"]}, {"http", "dast"})
        self.assertTrue(all(s["template_count"] == 1 for s in report["stages"]))
        self.assertEqual(len(calls), 4)

    def test_findings_exit_one_and_are_preserved_in_report(self):
        finding = {"template-id": "fixture-xss", "info": {"severity": "medium"},
                   "matched-at": "https://example.test/search?a=1&b=2"}
        code, report, _ = self.active("--no-dast", records=json.dumps(finding) + "\n")
        self.assertEqual(code, 1)
        self.assertEqual(report["status"], "completed")
        self.assertEqual({key: report["findings"][0][key] for key in finding}, finding)
        self.assertTrue(Path(report["findings"][0]["evidence_file"]).is_file())

    def test_scanner_failure_takes_precedence_over_findings_exit_status(self):
        finding = {"template-id": "fixture-xxe"}
        code, report, _ = self.active("--no-dast", records=json.dumps(finding) + "\n", scan_code=3)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["findings"][0]["template-id"], finding["template-id"])

    def test_missing_scanner_writes_an_incomplete_report(self):
        code, report, calls = self.active(installed=False)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(calls, [])
        self.assertIn("Nuclei not found", " ".join(report["diagnostics"]))

    def test_missing_template_directory_cannot_report_clean_scan(self):
        (self.templates / "http").rmdir()
        code, report, calls = self.active("--no-dast")
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(calls, [])
        stage = next(s for s in report["stages"] if s["name"] == "http")
        self.assertIn("Missing local template directory", stage["error"])

    def test_empty_or_failed_inventory_prevents_scanning(self):
        for inventory, inventory_code in (("", 0), ("fixture.yaml\n", 1)):
            with self.subTest(inventory=inventory, inventory_code=inventory_code):
                code, report, calls = self.active(inventory=inventory, inventory_code=inventory_code)
                self.assertEqual(code, 2)
                self.assertEqual(report["status"], "incomplete")
                self.assertTrue(all("-tl" in command for command, _ in calls))
                self.assertTrue(all(s["status"] == "error" for s in report["stages"]))

    def test_inventory_and_scan_use_identical_filters_and_isolated_config(self):
        _, report, calls = self.active()
        for offset in (0, 2):
            inventory, inventory_options = calls[offset]
            scan, scan_options = calls[offset + 1]
            self.assertEqual(inventory[:-2], scan[:scan.index("-l")])
            self.assertEqual(inventory[-2:], ["-tl", "-silent"])
            for flag in ("-dr", "-duc", "-dut", "-ni"):
                self.assertIn(flag, scan)
            self.assertEqual(scan[scan.index("-pt") + 1], "http")
            config = Path(scan[scan.index("-config") + 1])
            self.assertTrue(config.is_relative_to(self.web / "assessments"))
            self.assertEqual(config.read_text(encoding="utf-8"), "{}\n")
            target_file = Path(scan[scan.index("-l") + 1])
            if "-dast" in scan:
                self.assertEqual(scan[scan.index("-im") + 1], "burp")
                captures = WEB_ASSESS.load_requests([target_file], WEB_ASSESS.Scope(self.workspace, []))
                self.assertEqual([item["url"] for item in captures], ["https://example.test/search?a=1&b=2"])
            else:
                self.assertEqual(target_file.read_text(encoding="utf-8"), "https://example.test/search?a=1&b=2\n")
            self.assertFalse(scan_options.get("shell", False))
            self.assertFalse(inventory_options.get("shell", False))
        http, dast = [s for s in report["stages"] if "command" in s]
        self.assertNotIn("-dast", http["command"])
        self.assertIn("-dast", dast["command"])
        self.assertEqual(dast["command"][dast["command"].index("-fa") + 1], "low")
        self.assertEqual(http["command"][http["command"].index("-etags") + 1], "dos,bruteforce,fuzz,headless")
        self.assertEqual(dast["command"][dast["command"].index("-etags") + 1], "dos,bruteforce,headless")

    def test_oast_requires_explicit_opt_in_for_inventory_and_scan(self):
        _, report, calls = self.active("--oast")
        self.assertTrue(report["oast_enabled"])
        self.assertTrue(all("-ni" not in command for command, _ in calls))

    def test_inherited_proxy_settings_are_not_used(self):
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://bad-proxy.invalid", "https_proxy": "https://bad-proxy.invalid", "ALL_PROXY": "socks://bad-proxy.invalid"}):
            _, _, calls = self.active("--no-dast")
        for _, options in calls:
            self.assertFalse({"http_proxy", "https_proxy", "all_proxy"} & {k.lower() for k in options["env"]})

    def test_scan_timeout_writes_report_and_error_log(self):
        code, report, _ = self.active("--no-dast", exception=subprocess.TimeoutExpired("fake-nuclei", 1))
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "incomplete")
        stage = next(s for s in report["stages"] if s["name"] == "http")
        self.assertEqual(stage["returncode"], 124)
        log = Path(stage["findings_file"]).with_suffix(".log")
        self.assertIn("exceeded its timeout", log.read_text(encoding="utf-8"))

    def test_bad_jsonl_cannot_be_reported_as_no_findings(self):
        for records in ("{broken\n", "{}\n", "[]\n", "null\n"):
            with self.subTest(records=records):
                code, report, _ = self.active("--no-dast", records=records)
                self.assertEqual(code, 2)
                self.assertEqual(report["status"], "incomplete")
                self.assertIn("Invalid JSONL", " ".join(report["diagnostics"]))

    def test_dry_run_never_executes_scanner_or_crawler(self):
        argv = ["--workspace", str(self.workspace), "--templates", str(self.templates),
                "--url", "https://example.test/search?a=1&b=2", "--dry-run"]
        with mock.patch.object(WEB_ASSESS.subprocess, "run", side_effect=AssertionError("No subprocesses in dry run")), \
                mock.patch.object(WEB_ASSESS.urllib.request, "build_opener", side_effect=AssertionError("No networking in dry run")), \
                contextlib.redirect_stdout(io.StringIO()):
            code = WEB_ASSESS.main(argv)
        self.assertEqual(code, 0)
        self.assertEqual(self.latest_report()["status"], "planned")

    def test_truncated_crawl_cannot_be_reported_as_complete(self):
        info = {"visited": 1, "limited": True, "diagnostics": [], "forms": []}
        code, report, _ = self.active("--no-dast", crawl_info=info)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "incomplete")
        self.assertTrue(report["crawl"]["limited"])

    def test_crawl_failure_cannot_be_reported_as_complete(self):
        info = {"visited": 1, "limited": False, "diagnostics": ["Crawl failed: timeout"], "forms": []}
        code, report, _ = self.active("--no-dast", crawl_info=info)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "incomplete")
        self.assertIn("Crawl failed: timeout", report["diagnostics"])


class WebCrawlerTests(unittest.TestCase):
    """Exercise redirects and form discovery against loopback-only HTTP fixtures."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp.name)
        (self.workspace / ".target.env").write_text('IP="127.0.0.1"\n', encoding="utf-8")
        self.requests = []
        requests = self.requests

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                if self.path in ("/slow-body", "/slow-headers"):
                    if self.path == "/slow-headers":
                        self.wfile.write(b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nX-Slow: ")
                    else:
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html")
                        self.end_headers()
                    try:
                        for _ in range(40):
                            self.wfile.write(b"x")
                            self.wfile.flush()
                            time.sleep(0.1)
                    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                        pass
                    return
                if self.path in ("/redirect", "/external-redirect"):
                    self.send_response(302)
                    self.send_header("Location", "/one" if self.path == "/redirect" else "http://outside.invalid/escape")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html" if self.path in ("/", "/large") else "text/plain")
                self.end_headers()
                if self.path == "/":
                    self.wfile.write((
                        '<a href="/one">One</a>'
                        '<a href="http://outside.invalid/outside">Outside</a>'
                        f'<a href="http://localhost:{self.server.server_port}/other-host">Other host</a>'
                        '<a href="/search?a=1&amp;b=2#fragment">Search</a>'
                        '<form method="get" action="/find">'
                        '<input name="query" value="hello world">'
                        '<input type="hidden" name="csrf" value="secret">'
                        '<input type="password" name="password" value="secret">'
                        '</form>'
                        '<form method="post" action="/submit"><input name="body"></form>'
                    ).encode("utf-8"))
                elif self.path == "/large":
                    self.wfile.write(b"x" * (1024 * 1024 + 100))
                else:
                    self.wfile.write(b"fixture")

            def log_message(self, format, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.scope = WEB_ASSESS.Scope(self.workspace, [])

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temp.cleanup()

    def crawl(self, path="/", *args):
        options = WEB_ASSESS.arguments([
            "--rate-limit", "1000", "--request-timeout", "2", "--crawl-timeout", "5", *args,
        ])
        # Prevent a regression from making any request beyond this fixture.
        original_fetch = WEB_ASSESS.fetch_page

        def guarded_fetch(url, *a, **kw):
            if WEB_ASSESS.origin(url) != self.base:
                self.fail(f"Crawler attempted a request outside fixture origin: {url}")
            return original_fetch(url, *a, **kw)

        with mock.patch.object(WEB_ASSESS, "fetch_page", new=guarded_fetch):
            return WEB_ASSESS.crawl([self.base + path], self.scope, options)

    def test_links_and_get_forms_are_collected_without_submitting_forms(self):
        endpoints, info = self.crawl()
        self.assertEqual(info["diagnostics"], [])
        self.assertCountEqual(self.requests, ["/", "/one", "/search?a=1&b=2"])
        self.assertCountEqual(endpoints, [
            self.base + "/", self.base + "/one", self.base + "/search?a=1&b=2",
        ])
        self.assertEqual(len(info["forms"]), 2)
        self.assertEqual(info["forms"][0]["field_names"], ["query", "csrf", "password"])
        self.assertTrue(all(form["status"] == "prepared" for form in info["forms"]))
        self.assertNotIn("secret", json.dumps(info))

    def test_redirects_are_checked_before_following_same_origin(self):
        endpoints, info = self.crawl("/redirect")
        self.assertEqual(info["diagnostics"], [])
        self.assertEqual(self.requests, ["/redirect", "/one"])
        self.assertCountEqual(endpoints, [self.base + "/redirect", self.base + "/one"])

    def test_external_redirect_is_never_followed(self):
        endpoints, info = self.crawl("/external-redirect")
        self.assertIn("Blocked redirect", " ".join(info["diagnostics"]))
        self.assertEqual(self.requests, ["/external-redirect"])
        self.assertEqual(endpoints, [self.base + "/external-redirect"])

    def test_page_limit_bounds_requests_and_is_reported(self):
        _, info = self.crawl("/", "--max-pages", "1")
        self.assertEqual(self.requests, ["/"])
        self.assertEqual(info["visited"], 1)
        self.assertTrue(info["limited"])

    def test_endpoint_limit_bounds_scanner_inputs(self):
        endpoints, info = self.crawl("/", "--max-endpoints", "2")
        self.assertEqual(len(endpoints), 2)
        self.assertTrue(info["limited"])

    def test_oversized_html_is_bounded_and_reported_as_truncated(self):
        _, info = self.crawl("/large")
        self.assertTrue(info["limited"])

    def test_trickling_body_cannot_extend_total_request_deadline(self):
        started = time.monotonic()
        _, info = self.crawl("/slow-body", "--request-timeout", "1", "--crawl-timeout", "1")
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertTrue(info["diagnostics"])
        self.assertEqual(self.requests, ["/slow-body"])

    def test_trickling_headers_cannot_extend_total_request_deadline(self):
        started = time.monotonic()
        _, info = self.crawl("/slow-headers", "--request-timeout", "1", "--crawl-timeout", "1")
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertTrue(info["diagnostics"])
        self.assertEqual(self.requests, ["/slow-headers"])


if __name__ == "__main__":
    unittest.main()
