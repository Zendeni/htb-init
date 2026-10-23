"""Session and complete-request regressions; HTTP fixtures are loopback only."""
import base64
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import tempfile
import threading
import unittest
from unittest import mock
import urllib.parse


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("web_sessions_subject", ROOT / "web-assess.py")
WEB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WEB)


class SessionInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp.name) / "workspace"
        self.workspace.mkdir()
        (self.workspace / ".target.env").write_text('IP="127.0.0.1"\n', encoding="utf-8")
        self.templates = Path(self.temp.name) / "templates"
        (self.templates / "http").mkdir(parents=True)
        (self.templates / "dast").mkdir()
        self.seen = []
        seen = self.seen

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append({"method": "GET", "path": self.path, "headers": dict(self.headers), "body": b"", "port": self.server.server_port})
                status, body = 200, "fixture"
                has_anon = "anon=session" in self.headers.get("Cookie", "")
                if self.path == "/":
                    body = '<a href="/catalog?page=1">Catalog</a>'
                elif self.path == "/catalog?page=1":
                    status = 200 if has_anon else 403
                    body = '<a href="/catalog?page=2">More</a>'
                elif self.path == "/catalog?page=2":
                    status = 200 if has_anon else 403
                    body = ('<form method="post" action="/submit">'
                            '<input type="hidden" name="csrf" value="token123">'
                            '<textarea name="description">hello\nworld</textarea>'
                            '<select name="plan"><option value="wrong">One</option><option selected value="chosen">Two</option></select>'
                            '<input type="checkbox" checked name="agree" value="yes">'
                            '<input type="checkbox" name="ignored" value="no">'
                            '</form>')
                elif self.path == "/auth":
                    status = 200 if self.headers.get("Authorization") == "Bearer fixture-secret" else 401
                elif self.path == "/forbidden":
                    status = 403
                elif self.path == "/expired":
                    status = 302
                self.send_response(status)
                self.send_header("Content-Type", "text/html")
                if self.path == "/":
                    self.send_header("Set-Cookie", "anon=session; Path=/; HttpOnly")
                if self.path == "/expired":
                    self.send_header("Location", "/login")
                self.end_headers()
                self.wfile.write(body.encode())

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                seen.append({"method": "POST", "path": self.path, "headers": dict(self.headers), "body": body, "port": self.server.server_port})
                status = 200
                if self.path == "/api" and self.headers.get("Authorization") != "Bearer fixture-secret":
                    status = 401
                if self.path == "/submit" and ("anon=session" not in self.headers.get("Cookie", "") or b"csrf=token123" not in body):
                    status = 403
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{}')

            def log_message(self, *args):
                pass

        self.servers = [ThreadingHTTPServer(("127.0.0.1", 0), Handler) for _ in range(2)]
        self.threads = []
        for server in self.servers:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
            thread.start()
            self.threads.append(thread)
        self.base, self.other = [f"http://127.0.0.1:{server.server_port}" for server in self.servers]
        self.scope = WEB.Scope(self.workspace, [])

    def tearDown(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)
        self.temp.cleanup()

    def json_file(self, name, value):
        path = Path(self.temp.name) / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def session(self, headers=None, cookies=None):
        return self.json_file("session.json", {"origins": {self.base: {"headers": headers or {"Authorization": "Bearer fixture-secret"}, "cookies": cookies or {"authcookie": "fixture-cookie"}}}})

    def captures(self, *records):
        return self.json_file("requests.json", {"requests": records})

    def latest(self):
        parent = self.workspace / "enum" / "web" / "assessments"
        pointer = json.loads((parent / "latest.json").read_text())
        path = parent / pointer["run_id"] / "report.json"
        return json.loads(path.read_text()), path.parent

    def active(self, *extra, findings="", runtime_error=False, interrupt=False):
        commands = []

        def scanner(command, log, timeout):
            commands.append(command)
            log.write_text("fixture.yaml\n" if "-tl" in command else "fixture scan\n", encoding="utf-8")
            if "-tl" not in command:
                Path(command[command.index("-o") + 1]).write_text(findings, encoding="utf-8")
                if runtime_error:
                    Path(command[command.index("-elog") + 1]).write_text('{"error":"connection reset"}\n', encoding="utf-8")
                if interrupt:
                    raise WEB.AssessmentInterrupted(signal.SIGTERM)
            return 0

        with mock.patch.object(WEB.shutil, "which", return_value="fixture-nuclei"), \
                mock.patch.object(WEB, "run_command", side_effect=scanner), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = WEB.main(["--workspace", str(self.workspace), "--templates", str(self.templates),
                             "--url", self.base + "/", "--rate-limit", "1000", "--request-timeout", "2", "--crawl-timeout", "4", *map(str, extra)])
        report, output = self.latest()
        return code, report, output, commands

    def test_anonymous_session_query_navigation_and_complete_post_form(self):
        code, report, output, _ = self.active()
        self.assertEqual(code, 0, report["diagnostics"])
        pages = [request["path"] for request in self.seen if request["method"] == "GET"]
        self.assertIn("/catalog?page=1", pages)
        self.assertIn("/catalog?page=2", pages)
        posts = [request for request in self.seen if request["method"] == "POST"]
        self.assertEqual(len(posts), 1, "Only the unmutated form baseline is sent by Python")
        self.assertIn("anon=session", posts[0]["headers"].get("Cookie", ""))
        values = urllib.parse.parse_qs(posts[0]["body"].decode())
        self.assertEqual(values, {"csrf": ["token123"], "description": ["hello\r\nworld"], "plan": ["chosen"], "agree": ["yes"]})
        records = WEB.load_requests([output / "requests.burp.xml"], self.scope)
        form = next(request for request in records if request["method"] == "POST")
        self.assertEqual(form["body"], posts[0]["body"])
        self.assertIn("anon=session", form["headers"]["cookie"])
        self.assertNotIn("token123", (output / "report.json").read_text())

    def test_session_auth_and_cookies_never_cross_origins(self):
        options = WEB.arguments([])
        options.sessions = WEB.Sessions(self.session(), self.scope)
        response = WEB.fetch_page(self.base + "/auth", options, 2)
        self.assertEqual(response["status"], 200)
        WEB.fetch_page(self.other + "/auth", options, 2)
        first, second = self.seen
        self.assertEqual(first["headers"].get("Authorization"), "Bearer fixture-secret")
        self.assertIn("authcookie=fixture-cookie", first["headers"].get("Cookie", ""))
        self.assertNotIn("Authorization", second["headers"])
        self.assertNotIn("Cookie", second["headers"])

    def test_captured_json_and_xml_bodies_reach_baseline_and_burp_unchanged(self):
        bodies = [("application/json", '{"message":"hello & world"}'), ("application/xml", '<root attr="value">hello &amp; world</root>')]
        captures = self.captures(*[{"method": "POST", "url": self.base + "/api", "headers": {"Content-Type": kind}, "body": body} for kind, body in bodies])
        code, report, output, commands = self.active("--no-crawl", "--session-file", self.session(), "--requests-file", captures)
        self.assertEqual(code, 0, report["diagnostics"])
        actual = [request for request in self.seen if request["method"] == "POST"]
        self.assertCountEqual([request["body"] for request in actual], [body.encode() for _, body in bodies])
        self.assertTrue(all(request["headers"]["Authorization"] == "Bearer fixture-secret" for request in actual))
        exported = WEB.load_requests([output / "requests.burp.xml"], self.scope)
        self.assertCountEqual([request["body"] for request in exported if request["method"] == "POST"], [body.encode() for _, body in bodies])
        scan = next(command for command in commands if "-dast" in command and "-l" in command)
        self.assertEqual(scan[scan.index("-im") + 1], "burp")
        for name in ("report.json", "report.md"):
            self.assertNotIn("fixture-secret", (output / name).read_text())

    def test_expired_api_session_is_incomplete_even_when_root_is_public(self):
        capture = self.captures({"method": "POST", "url": self.base + "/api", "headers": {"Authorization": "Bearer expired", "Content-Type": "application/json"}, "body": '{"id":1}'})
        code, report, _, _ = self.active("--no-crawl", "--requests-file", capture)
        self.assertEqual(code, 2)
        self.assertEqual(report["preflight"][0]["status"], 200)
        self.assertEqual(report["request_checks"][0]["status"], 401)
        self.assertIn("Baseline HTTP 401", " ".join(report["diagnostics"]))

    def test_login_redirect_is_reported_as_invalid_session(self):
        capture = self.captures({"url": self.base + "/expired"})
        code, report, _, _ = self.active("--no-crawl", "--requests-file", capture)
        self.assertEqual(code, 2)
        self.assertIn("session appears expired", " ".join(report["diagnostics"]))

    def test_nuclei_request_errors_cannot_report_clean_success(self):
        code, report, _, _ = self.active("--no-crawl", runtime_error=True)
        self.assertEqual(code, 2)
        self.assertTrue(all(stage["status"] == "error" for stage in report["stages"]))
        self.assertTrue(all(stage["request_errors"] == 1 for stage in report["stages"]))

    def test_sigterm_preserves_partial_findings_and_atomic_latest_report(self):
        finding = {"template-id": "fixture-sqli", "request": "Authorization: secret", "response": "secret response", "info": {"severity": "high"}}
        code, report, output, _ = self.active("--no-crawl", interrupt=True, findings=json.dumps(finding) + "\n")
        self.assertEqual(code, 128 + signal.SIGTERM)
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["findings"][0]["template-id"], "fixture-sqli")
        self.assertNotIn("request", report["findings"][0])
        self.assertNotIn("response", report["findings"][0])
        self.assertIn("Authorization: secret", (output / "http.jsonl").read_text())
        self.assertEqual(report["stages"][0]["status"], "error")
        self.assertFalse(list(output.glob("*.tmp")))

    def test_latest_pointer_changes_on_invalid_attempt(self):
        _, _, first, _ = self.active("--dry-run")
        _, report, second, _ = self.active("--url", "http://outside.invalid/", "--dry-run")
        self.assertNotEqual(first, second)
        self.assertEqual(report["status"], "incomplete")

    def test_unreachable_preflight_skips_all_scanner_commands(self):
        with mock.patch.object(WEB, "preflight", return_value=[{"origin": self.base, "reachable": False, "error": "name resolution failed"}]):
            code, report, _, commands = self.active("--no-crawl")
        self.assertEqual(code, 2)
        self.assertEqual(commands, [])
        self.assertIn("name resolution failed", " ".join(report["diagnostics"]))

    def test_request_scope_and_host_header_are_validated_before_scanning(self):
        for record in ({"url": "http://outside.invalid/"}, {"url": self.base + "/", "headers": {"Host": "outside.invalid"}}, {"url": self.base + "/", "headers": {"X-Test": "ok\r\nHost: outside.invalid"}}):
            with self.subTest(record=record):
                with self.assertRaises(ValueError):
                    WEB.load_requests([self.captures(record)], self.scope)

    def test_session_scope_and_header_injection_are_rejected(self):
        for origin, headers in (("http://outside.invalid", {}), (self.base + "/path", {}), (self.base, {"Authorization": "good\nX-Test: bad"})):
            with self.subTest(origin=origin, headers=headers):
                path = self.json_file("bad-session.json", {"origins": {origin: {"headers": headers}}})
                with self.assertRaises(ValueError):
                    WEB.Sessions(path, self.scope)

    def test_binary_body_roundtrip_and_normal_burp_doctype(self):
        body = b"\x00\xff\r\nbody"
        captures = self.captures({"method": "POST", "url": self.base + "/api", "body_base64": base64.b64encode(body).decode()})
        records = WEB.load_requests([captures], self.scope)
        burp = Path(self.temp.name) / "roundtrip.xml"
        WEB.export_burp(burp, records, WEB.Sessions())
        xml = burp.read_text()
        xml = xml.replace("<items ", '<!DOCTYPE items [<!ELEMENT items (item*)>]>\n<items ', 1)
        burp.write_text(xml)
        self.assertEqual(WEB.load_requests([burp], self.scope)[0]["body"], body)

    def test_burp_entities_are_rejected_without_expansion(self):
        path = Path(self.temp.name) / "entities.xml"
        path.write_text('<!DOCTYPE items [<!ENTITY secret SYSTEM "file:///missing">]><items>&secret;</items>')
        with self.assertRaises(ValueError):
            WEB.load_requests([path], self.scope)

    def test_ambiguous_and_missing_required_form_values_are_not_invented(self):
        for markup in ('<input required name="q">', '<input type="file" name="file">', '<input type="checkbox" required name="agree">', '<button name="operation" value="delete">Delete</button>'):
            with self.subTest(markup=markup):
                parser = WEB.Links()
                parser.feed('<form action="/submit" method="post">' + markup + '</form>')
                request, reason = WEB.form_request(parser.forms[0], self.base + "/", self.base + "/")
                self.assertIsNone(request)
                self.assertTrue(reason)

    def test_get_form_preserves_hidden_selected_and_textarea_values(self):
        parser = WEB.Links()
        parser.feed('<form action="/find"><input type="hidden" name="csrf" value="token"><textarea name="q">hello world</textarea><select name="pick"><option>first</option><option selected value="second">two</option></select></form>')
        request, reason = WEB.form_request(parser.forms[0], self.base + "/", self.base + "/")
        self.assertIsNone(reason)
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(request["url"]).query), {"csrf": ["token"], "q": ["hello world"], "pick": ["second"]})
        self.assertEqual(request["body"], b"")

    @unittest.skipIf(os.name == "nt", "Unix file-mode check")
    def test_capture_artifact_permissions_are_private(self):
        _, _, output, _ = self.active("--dry-run")
        self.assertEqual((output / "requests.burp.xml").stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
