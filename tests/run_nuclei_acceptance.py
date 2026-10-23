#!/usr/bin/env python3
"""Opt-in acceptance tests using real Nuclei and signed templates on loopback only.

Run separately from unittest discovery. Requires existing scanner/template paths;
does not install tools or contact a vulnerability API or callback service.
"""
from __future__ import annotations

import argparse
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from urllib.parse import parse_qs, unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
SIGNED_TEMPLATES = {
    "http/nginx-version.yaml": "http/technologies/nginx/nginx-version.yaml",
    "dast/reflected-xss.yaml": "dast/vulnerabilities/xss/reflected-xss.yaml",
    "dast/sqli-error-based.yaml": "dast/vulnerabilities/sqli/sqli-error-based.yaml",
}


def fixture(vulnerable):
    received = []

    class Handler(BaseHTTPRequestHandler):
        server_version = "nginx/1.24.0"
        sys_version = ""

        def log_message(self, *_):
            pass

        def respond(self, body, status=200, cookie=False):
            raw = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            if cookie:
                self.send_header("Set-Cookie", "lab=server-issued; HttpOnly; Path=/")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            parsed = urlsplit(self.path)
            received.append({"method": "GET", "path": self.path})
            if parsed.path == "/":
                self.respond('<a href="/catalog?page=1">Catalog</a>', cookie=True)
            elif parsed.path == "/catalog":
                if "lab=server-issued" not in self.headers.get("Cookie", ""):
                    self.respond("Session required", 403)
                elif parse_qs(parsed.query).get("page") == ["2"]:
                    self.respond('<form action="/submit" method="post">'
                                 '<input type="hidden" name="csrf" value="fixed-nonce">'
                                 '<textarea name="q">hello</textarea>'
                                 '<select name="category"><option value="books" selected>Books</option></select>'
                                 '</form>')
                else:
                    self.respond('<a href="/catalog?page=2">Next page</a>')
            else:
                self.respond("Fixture endpoint")

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode(errors="replace")
            content_type = self.headers.get("Content-Type", "")
            path = urlsplit(self.path).path
            cookie_ok = "lab=server-issued" in self.headers.get("Cookie", "")
            auth_ok = self.headers.get("Authorization") == "Bearer loopback-fixture"
            entry = {"method": "POST", "path": path, "body": raw,
                     "content_type": content_type, "cookie_ok": cookie_ok, "auth_ok": auth_ok}
            received.append(entry)
            if path == "/submit":
                fields = parse_qs(raw, keep_blank_values=True)
                entry["csrf_ok"] = fields.get("csrf") == ["fixed-nonce"]
                if not cookie_ok or not entry["csrf_ok"]:
                    self.respond("Session or CSRF failed", 403)
                    return
                values = fields.get("q", []) + fields.get("category", [])
            elif path == "/api/json":
                if not auth_ok:
                    self.respond("Authentication required", 401)
                    return
                try:
                    fields = json.loads(raw)
                    values = [str(value) for value in fields.values()]
                except (ValueError, AttributeError):
                    self.respond("Invalid JSON", 400)
                    return
            elif path == "/api/xml":
                if not auth_ok:
                    self.respond("Authentication required", 401)
                    return
                # No entity expansion: this fixture tests XML request transport,
                # not a real XXE vulnerability or local-file disclosure.
                values = [html.unescape(value) for value in re.findall(r">([^<]*)<", raw)]
            else:
                self.respond("Missing fixture", 404)
                return
            reflected = " ".join(unquote(value) for value in values)
            if vulnerable and any(char in reflected for char in ("'", '"', ";")):
                reflected += " SQL syntax error for MySQL"
            self.respond("<html><body>" + (reflected if vulnerable else html.escape(reflected)) + "</body></html>")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, received


def run_case(args, run, name, vulnerable):
    case = run / name
    workspace = case / "workspace"
    workspace.mkdir(parents=True)
    (workspace / ".target.env").write_text('IP="127.0.0.1"\nHOST="127.0.0.1"\n', encoding="utf-8")
    server, thread, received = fixture(vulnerable)
    origin = f"http://127.0.0.1:{server.server_port}"
    session = case / "session.json"
    session.write_text(json.dumps({"origins": {origin: {"headers": {"Authorization": "Bearer loopback-fixture"}}}}), encoding="utf-8")
    captured = case / "requests.json"
    captured.write_text(json.dumps({"requests": [
        {"method": "POST", "url": origin + "/api/json", "headers": {"Content-Type": "application/json"}, "body": '{"q":"hello"}'},
        {"method": "POST", "url": origin + "/api/xml", "headers": {"Content-Type": "application/xml"}, "body": '<request><q>hello</q></request>'},
    ]}), encoding="utf-8")
    command = [sys.executable, "-I", str(ROOT / "web-assess.py"), "--workspace", str(workspace),
               "--url", origin + "/", "--templates", str(run / "templates"), "--nuclei", str(args.nuclei),
               "--session-file", str(session), "--requests-file", str(captured),
               "--scan-timeout", "90", "--request-timeout", "5", "--crawl-timeout", "30",
               "--max-pages", "8", "--rate-limit", "50", "--concurrency", "1"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", env=args.env, timeout=240)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
    (case / "stdout.log").write_text(result.stdout, encoding="utf-8")
    (case / "stderr.log").write_text(result.stderr, encoding="utf-8")
    (case / "received.json").write_text(json.dumps(received, indent=2), encoding="utf-8")
    paths = sorted((workspace / "enum/web/assessments").glob("*/report.json"))
    report = json.loads(paths[-1].read_text(encoding="utf-8")) if paths else {}
    ids = {record.get("template-id") for record in report.get("findings", [])}
    posts = [entry for entry in received if entry["method"] == "POST"]
    positive_post = lambda entry: entry["body"] not in ('{"q":"hello"}', '<request><q>hello</q></request>') and "hello" in entry["body"]
    checks = {
        "assessment_completed": report.get("status") == "completed",
        "query_navigation_followed": any(entry["path"] == "/catalog?page=2" for entry in received),
        "post_form_tested_with_session_and_csrf": any(entry["path"] == "/submit" and entry.get("cookie_ok") and entry.get("csrf_ok") and (parse_qs(entry["body"]).get("q") != ["hello"] or parse_qs(entry["body"]).get("category") != ["books"]) for entry in posts),
        "authenticated_json_mutated": any(entry["path"] == "/api/json" and entry["auth_ok"] and "application/json" in entry["content_type"] and positive_post(entry) for entry in posts),
        "authenticated_xml_mutated": any(entry["path"] == "/api/xml" and entry["auth_ok"] and "application/xml" in entry["content_type"] and positive_post(entry) for entry in posts),
        "positive_findings" if vulnerable else "negative_control": {"reflected-xss", "sqli-error-based"}.issubset(ids) if vulnerable else not ({"reflected-xss", "sqli-error-based"} & ids),
    }
    analysis = subprocess.run([sys.executable, "-I", str(ROOT / "analyze-recon.py"), str(workspace)],
                              capture_output=True, text=True, encoding="utf-8", timeout=60)
    (case / "analysis.log").write_text(analysis.stdout + analysis.stderr, encoding="utf-8")
    overview_path = workspace / "overview.json"
    overview = json.loads(overview_path.read_text(encoding="utf-8")) if overview_path.exists() else {}
    routes = overview.get("routes", [])
    checks["overview_created"] = analysis.returncode == 0 and bool(overview)
    checks["overview_short"] = len(routes) <= 3
    if vulnerable:
        checks["findings_reach_attack_paths"] = bool(routes) and any("sqli" in json.dumps(route).lower() or "sql injection" in json.dumps(route).lower() for route in routes)
    return {"name": name, "passed": all(checks.values()), "checks": checks,
            "helper_returncode": result.returncode, "status": report.get("status"),
            "finding_ids": sorted(ids), "requests_received": len(received),
            "post_requests_received": len(posts), "diagnostics": report.get("diagnostics"),
            "workspace": str(workspace), "overview": str(overview_path)}


def unreachable_case(args, run):
    workspace = run / "unreachable/workspace"
    workspace.mkdir(parents=True)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        target = f"http://127.0.0.1:{sock.getsockname()[1]}/"
    result = subprocess.run([sys.executable, "-I", str(ROOT / "web-assess.py"), "--workspace", str(workspace),
                             "--allow-host", "127.0.0.1", "--url", target,
                             "--templates", str(run / "templates"), "--nuclei", str(args.nuclei),
                             "--no-crawl", "--no-dast", "--request-timeout", "2", "--scan-timeout", "30"],
                            capture_output=True, text=True, encoding="utf-8", env=args.env, timeout=90)
    paths = sorted((workspace / "enum/web/assessments").glob("*/report.json"))
    report = json.loads(paths[-1].read_text(encoding="utf-8")) if paths else {}
    return {"name": "unreachable", "passed": result.returncode == 2 and report.get("status") in ("incomplete", "partial"),
            "helper_returncode": result.returncode, "status": report.get("status"), "diagnostics": report.get("diagnostics")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nuclei", required=True, type=Path)
    parser.add_argument("--templates", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.nuclei = args.nuclei.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="nuclei-acceptance-", dir=args.output))
    for destination, source in SIGNED_TEMPLATES.items():
        target = run / "templates" / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.templates / source, target)
    args.env = dict(os.environ)
    args.env["NUCLEI_TEMPLATES_DIR"] = str(run / "templates")
    for provider in ("PUBLIC", "GITHUB", "GITLAB", "AWS", "AZURE"):
        args.env[f"DISABLE_NUCLEI_TEMPLATES_{provider}_DOWNLOAD"] = "true"
    for key in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "APPDATA", "LOCALAPPDATA"):
        path = run / key.lower()
        path.mkdir()
        args.env[key] = str(path)
        # Nuclei normally installs this data beside its user configuration.
        # Keep the acceptance environment complete without allowing downloads.
        config = path / "nuclei"
        config.mkdir()
        shutil.copyfile(args.templates / ".nuclei-ignore", config / ".nuclei-ignore")
    cases = [run_case(args, run, "vulnerable", True), run_case(args, run, "escaped", False), unreachable_case(args, run)]
    summary = {"passed": all(case["passed"] for case in cases), "cases": cases, "artifacts": str(run)}
    (run / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
