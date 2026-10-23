#!/usr/bin/env python3
"""Bounded web assessment for HTB workspaces; Python 3.10+, no Python dependencies.

Nuclei and a local nuclei-templates checkout are required for active assessment.
Dry runs validate scope and save a plan without network access or subprocesses.
"""
from __future__ import annotations

import argparse
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


MANUAL = {
    "A01 Broken Access Control": "Compare two users/roles for IDOR, authorization, CSRF and SSRF; enable OAST for blind SSRF.",
    "A02 Security Misconfiguration": "Review headers, CORS, debug/admin endpoints, XML parsers and XXE, cloud/server configuration.",
    "A03 Software Supply Chain Failures": "Review lockfiles, SBOM, build pipelines and dependency provenance; web CVE matches are partial coverage.",
    "A04 Cryptographic Failures": "Review TLS/ciphers, secrets, data storage, key handling and transport of credentials.",
    "A05 Injection": "Validate XSS, SQL/NoSQL, command, template and LDAP injection; capture POST/JSON/XML requests for body testing.",
    "A06 Insecure Design": "Review business rules, trust boundaries, abuse cases, workflow bypasses and race conditions.",
    "A07 Authentication Failures": "Test login, MFA, reset, session rotation, logout and account lifecycle with test accounts.",
    "A08 Software or Data Integrity Failures": "Review deserialization, update signatures, webhooks and integrity of trusted data.",
    "A09 Security Logging and Alerting Failures": "Verify server-side audit events and alert delivery for representative failures.",
    "A10 Mishandling of Exceptional Conditions": "Review errors, fail-open behavior, resource limits, rollback and recovery.",
}
LIMITS = [
    "Template matches are leads for verification; no matches do not prove an application is secure.",
    "Known HTTP templates include XSS, XXE, SSRF, CVEs, exposures and misconfigurations when present in the local template set.",
    "DAST templates mutate supplied parameterized URLs (including paths where a template specifies them). Generic POST/JSON/XML bodies, stored/DOM XSS and authenticated flows need manual requests/tools.",
    "Crawler follows same-origin links only, never submits forms, and does not render JavaScript.",
    "Nuclei templates are trusted scanner code; target filtering and disabled redirects are not a network sandbox.",
]


def canonical_host(value):
    value = value.strip().rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value):
            raise ValueError(f"Invalid host: {value!r}")
        if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in value.split(".")):
            raise ValueError(f"Invalid host: {value!r}")
        return value


def normalize_url(value):
    if any(ord(c) <= 32 or ord(c) == 127 for c in value) or "\\" in value:
        raise ValueError("URL contains whitespace, control characters or backslashes")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("Expected an HTTP(S) URL without embedded credentials")
    host = canonical_host(parsed.hostname)
    port = parsed.port  # validates numeric port and range
    if port == 0:
        raise ValueError("Port must be between 1 and 65535")
    authority = f"[{host}]" if ":" in host else host
    if port and port != (443 if parsed.scheme == "https" else 80):
        authority += f":{port}"
    return urllib.parse.urlunsplit((parsed.scheme, authority, parsed.path or "/", parsed.query, ""))


def origin(url):
    p = urllib.parse.urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def scope_entry(value):
    if not isinstance(value, str):
        raise ValueError("Scope entries must be strings")
    if "/" in value:
        return ipaddress.ip_network(value, strict=False)
    return canonical_host(value)


class Scope:
    def __init__(self, workspace, extra):
        include, exclude = [], []
        path = workspace / "scope.json"
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or not isinstance(data.get("include"), list) or not isinstance(data.get("exclude", []), list):
                raise ValueError("scope.json must contain include/exclude arrays")
            include, exclude = data["include"], data.get("exclude", [])
        else:
            env = workspace / ".target.env"
            if env.exists():
                # Never source shell metadata. Only recognize literal IP/HOST values.
                for line in env.read_text(encoding="utf-8").splitlines():
                    match = re.fullmatch(r'''(?:IP|HOST)=(?:"([A-Za-z0-9.:_-]+)"|'([A-Za-z0-9.:_-]+)'|([A-Za-z0-9.:_-]+))''', line.strip())
                    if match:
                        include.append(next(x for x in match.groups() if x is not None))
        self.include = [scope_entry(x) for x in include + extra]
        self.exclude = [scope_entry(x) for x in exclude]
        if not self.include:
            raise ValueError("No explicit scope: set IP/HOST in .target.env, scope.json include, or --allow-host")

    def allows(self, url):
        host = urllib.parse.urlsplit(url).hostname
        def matches(entry):
            if isinstance(entry, str):
                return host == entry
            try:
                return ipaddress.ip_address(host) in entry
            except ValueError:
                return False
        return not any(map(matches, self.exclude)) and any(map(matches, self.include))


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []
        self.forms = []
        self.form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("a", "iframe") and attrs.get("href" if tag == "a" else "src"):
            self.urls.append(attrs["href" if tag == "a" else "src"])
        if tag == "form":
            self.form = {"action": attrs.get("action", ""), "method": attrs.get("method", "get").lower(), "fields": []}
        if tag in ("input", "textarea", "select") and self.form is not None and attrs.get("name"):
            if attrs.get("type", "text").lower() not in ("password", "file", "submit", "button", "reset", "hidden"):
                self.form["fields"].append((attrs["name"], attrs.get("value", "test")))

    def handle_endtag(self, tag):
        if tag == "form" and self.form is not None:
            self.forms.append(self.form)
            self.form = None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_worker(url, timeout, insecure):
    """One bounded-size HTTP response. Parent kills this process at its deadline."""
    context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(url, headers={"User-Agent": "htb-init-web-assess/1.0"})
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read(1024 * 1024 + 1) if "text/html" in response.headers.get("Content-Type", "") else b""
        return {"status": response.status, "headers": dict(response.headers), "body": body[:1024 * 1024].decode("utf-8", errors="replace"), "truncated": len(body) > 1024 * 1024}


def fetch_page(url, args, remaining):
    # Socket timeouts alone cannot stop a server that continually trickles bytes.
    # A subprocess deadline bounds connection, headers AND body and leaves no
    # background request thread behind after timeout.
    result = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--_fetch", url,
                             str(args.request_timeout), "1" if args.insecure else "0"],
                            capture_output=True, text=True, encoding="utf-8",
                            timeout=min(args.request_timeout, remaining), check=False)
    if result.returncode:
        raise ValueError(result.stderr.strip() or "HTTP fetch failed")
    return json.loads(result.stdout)


def crawl(urls, scope, args):
    allowed_origins = {origin(u) for u in urls}
    pending, seen, endpoints, diagnostics, forms = deque(urls), set(), set(urls), [], []
    deadline = time.monotonic() + args.crawl_timeout
    limited = False
    while pending and len(seen) < args.max_pages and time.monotonic() < deadline:
        url = pending.popleft()
        if url in seen:
            continue
        seen.add(url)
        found = []
        try:
            response = fetch_page(url, args, max(0.1, deadline - time.monotonic()))
            headers = {k.lower(): v for k, v in response["headers"].items()}
            location = headers.get("location")
            if location and 300 <= response["status"] < 400:
                found.append(location)
            limited = limited or response.get("truncated", False)
            if "text/html" in headers.get("content-type", ""):
                parser = Links()
                parser.feed(response["body"])
                found.extend(parser.urls)
                for form in parser.forms:
                    forms.append({"page": url, "action": form["action"], "method": form["method"], "field_names": [x[0] for x in form["fields"]]})
                    if form["method"] == "get" and form["fields"]:
                        action = urllib.parse.urljoin(url, form["action"])
                        p = urllib.parse.urlsplit(action)
                        found.append(urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, urllib.parse.urlencode(form["fields"]), "")))
        except (OSError, ValueError, urllib.error.URLError, subprocess.TimeoutExpired) as error:
            diagnostics.append(f"Crawl failed for {url}: {error}")
        for item in found:
            try:
                candidate = normalize_url(urllib.parse.urljoin(url, item))
            except ValueError:
                continue
            if origin(candidate) not in allowed_origins or not scope.allows(candidate):
                continue
            if candidate not in endpoints:
                if len(endpoints) >= args.max_endpoints:
                    limited = True
                    continue
                endpoints.add(candidate)
                # Query links/forms go to DAST; don't submit discovered forms while crawling.
                if not urllib.parse.urlsplit(candidate).query:
                    pending.append(candidate)
        time.sleep(min(1 / args.rate_limit, max(0, deadline - time.monotonic())))
    return sorted(endpoints), {"visited": len(seen), "limited": limited or bool(pending), "diagnostics": diagnostics, "forms": forms}


def positive(value):
    result = int(value)
    if result < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return result


def default_templates_path():
    override = os.environ.get("NUCLEI_TEMPLATES")
    if override:
        return Path(override).expanduser()

    home = Path.home()
    candidates = (home / ".local" / "nuclei-templates", home / "nuclei-templates")
    for candidate in candidates:
        if (candidate / "http").is_dir() and (candidate / "dast").is_dir():
            return candidate
    return candidates[0]


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--url", action="append", default=[])
    parser.add_argument("--urls-file", type=Path)
    parser.add_argument("--allow-host", action="append", default=[], help="explicit additional hostname/IP; exclusions still apply")
    parser.add_argument("--templates", type=Path, default=default_templates_path(), help="local trusted nuclei-templates checkout (must have http/ and dast/); auto-detects ~/.local/nuclei-templates and ~/nuclei-templates")
    parser.add_argument("--nuclei", default="nuclei")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-crawl", action="store_true")
    parser.add_argument("--no-dast", action="store_true")
    parser.add_argument("--oast", action="store_true", help="enable Interactsh callbacks for blind SSRF/XXE; target must reach callback service")
    parser.add_argument("--insecure", action="store_true", help="allow self-signed TLS in crawler (Nuclei uses its own TLS behavior)")
    for name, default in (("rate-limit", 10), ("concurrency", 2), ("request-timeout", 10), ("scan-timeout", 900), ("crawl-timeout", 120), ("max-pages", 30), ("max-endpoints", 200)):
        parser.add_argument("--" + name, type=positive, default=default)
    return parser.parse_args(argv)


def run_command(command, log, timeout):
    with log.open("w", encoding="utf-8") as output:
        try:
            # No shell expansion; explicitly avoid inherited proxy configuration.
            env = {k: v for k, v in os.environ.items() if k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
            result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=timeout, env=env, check=False)
            return result.returncode
        except subprocess.TimeoutExpired:
            output.write("\nAssessment stage exceeded its timeout.\n")
            return 124
        except OSError as error:
            output.write(str(error))
            return 127


def assess_stage(name, targets, template_dir, args, output, config):
    prefix = output / name
    findings = prefix.with_suffix(".jsonl")
    templates = prefix.with_suffix(".templates.txt")
    select = [args.nuclei, "-config", str(config), "-t", str(template_dir), "-pt", "http", "-dut", "-dr", "-duc", "-nc", "-etags", "dos,bruteforce,fuzz,headless"]
    if not args.oast:
        select.append("-ni")
    if name == "dast":
        # -dast is required; ordinary scans do not load DAST templates.
        select += ["-dast", "-fa", "low"]
        select[select.index("dos,bruteforce,fuzz,headless")] = "dos,bruteforce,headless"
    command = select + ["-l", str(targets), "-rl", str(args.rate_limit), "-c", str(args.concurrency), "-bs", "1", "-timeout", str(args.request_timeout), "-retries", "0", "-jsonl", "-o", str(findings)]
    result = {"name": name, "status": "planned", "command": command, "findings_file": str(findings)}
    if args.dry_run:
        return result
    if not template_dir.is_dir():
        return dict(result, status="error", error=f"Missing local template directory: {template_dir}; install/update nuclei-templates first")
    # Inventory with identical filters; an empty template set must never look clean.
    code = run_command(select + ["-tl", "-silent"], templates, min(args.scan_timeout, 60))
    selected = [line for line in templates.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip().endswith((".yaml", ".yml"))]
    result["template_count"] = len(selected)
    if code or not selected:
        return dict(result, status="error", returncode=code, error="Template inventory failed or selected zero templates; inspect stage log")
    findings.touch()
    code = run_command(command, prefix.with_suffix(".log"), args.scan_timeout)
    result.update(status="completed" if code == 0 else "error", returncode=code)
    return result


def write_report(output, report):
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    lines = ["# Web assessment", "", f"Status: **{report['status']}**", "", f"Findings: {len(report['findings'])}", "", f"Blind OAST checks enabled: {report['oast_enabled']}", "", "## Stages", ""]
    for stage in report["stages"]:
        detail = stage.get("error") or stage.get("reason")
        lines.append(f"- {stage['name']}: {stage['status']}" + (f" — {detail}" if detail else ""))
    if report.get("crawl"):
        lines += ["", f"Crawl: {report['crawl']['visited']} pages visited; truncated by limits: {report['crawl']['limited']}."]
    if report["findings"]:
        lines += ["", "## Findings to verify", ""]
        for finding in report["findings"]:
            info = finding.get("info", {})
            if not isinstance(info, dict):
                info = {}
            lines.append(f"- {info.get('severity', 'unknown')}: {finding['template-id']} — {finding.get('matched-at', finding.get('host', 'see JSONL'))}")
    lines += ["", "## Diagnostics", ""] + [f"- {item}" for item in report["diagnostics"]]
    lines += ["", "## Coverage limits", ""] + [f"- {item}" for item in report["limits"]]
    lines += ["", "## OWASP Top 10:2025 manual review", ""]
    lines += [f"- [ ] **{name}**: {task}" for name, task in MANUAL.items()]
    lines += ["", "References: https://owasp.org/Top10/2025/ and https://docs.projectdiscovery.io/opensource/nuclei/running", "", "Raw Nuclei findings and stage logs are alongside this report. Inspect them before sharing; they can contain target data.", ""]
    (output / "report.md").write_text("\n".join(lines), encoding="utf-8")


def main(argv=None):
    args = arguments(argv)
    args.workspace = args.workspace.resolve()
    args.templates = args.templates.expanduser().resolve()
    if not args.workspace.is_dir():
        print("Workspace does not exist", file=sys.stderr)
        return 2
    parent = args.workspace / "enum" / "web" / "assessments"
    parent.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-"), dir=parent))
    report = {"schema_version": 1, "status": "incomplete", "targets": [], "stages": [], "findings": [], "diagnostics": [], "limits": list(LIMITS), "manual_review": MANUAL, "oast_enabled": args.oast}
    if not args.oast:
        report["limits"].append("OAST is disabled: blind callback-based SSRF/XXE templates are excluded. Enable --oast to include them.")
    exit_code = 2
    try:
        scope = Scope(args.workspace, args.allow_host)
        explicit = list(args.url)
        if args.urls_file:
            explicit += [line.strip() for line in args.urls_file.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
        candidates = [(u, True) for u in explicit]
        if not explicit:
            for name in ("live-web-urls.txt", "discovered-host-web-urls.txt"):
                path = args.workspace / "enum" / "web" / name
                if path.is_file():
                    candidates += [(u.strip(), False) for u in path.read_text(encoding="utf-8").splitlines() if u.strip()]
        targets = set()
        for value, strict in candidates:
            try:
                url = normalize_url(value)
                if not scope.allows(url):
                    raise ValueError("target outside explicit scope")
                targets.add(url)
            except ValueError as error:
                if strict:
                    raise ValueError(f"Invalid target {value!r}: {error}") from error
                report["diagnostics"].append(f"Skipped discovered target {value!r}: {error}")
        if not targets:
            raise ValueError("No in-scope web URLs; run recon or supply --url")
        if len(targets) > args.max_endpoints:
            raise ValueError("Target list exceeds --max-endpoints; split it or increase the limit")
        report["targets"] = sorted(targets)
        if not args.dry_run and not shutil.which(args.nuclei):
            raise ValueError("Nuclei not found; install ProjectDiscovery Nuclei and its templates")
        endpoints = sorted(targets)
        if not args.no_crawl and not args.dry_run:
            endpoints, report["crawl"] = crawl(endpoints, scope, args)
            report["diagnostics"] += report["crawl"]["diagnostics"]
            if report["crawl"]["limited"]:
                report["diagnostics"].append("Crawl truncated by page, endpoint, response-size or time limits; discovery is partial.")
        report["endpoints"] = endpoints
        config = output / "nuclei-config.yaml"
        config.write_text("{}\n", encoding="utf-8")
        target_file = output / "targets.txt"
        target_file.write_text("\n".join(endpoints) + "\n", encoding="utf-8")
        stages = [("http", target_file, args.templates / "http")]
        parameterized = [u for u in endpoints if urllib.parse.urlsplit(u).query]
        if args.no_dast or not parameterized:
            report["stages"].append({"name": "dast", "status": "skipped", "reason": "disabled" if args.no_dast else "no query parameters discovered"})
        else:
            parameter_file = output / "parameters.txt"
            parameter_file.write_text("\n".join(parameterized) + "\n", encoding="utf-8")
            stages.append(("dast", parameter_file, args.templates / "dast"))
        for name, inputs, templates in stages:
            print(f"[+] Web assessment: {name}", flush=True)
            stage = assess_stage(name, inputs, templates, args, output, config)
            report["stages"].append(stage)
            findings = Path(stage["findings_file"])
            if findings.is_file():
                for line in findings.read_text(encoding="utf-8", errors="replace").splitlines():
                    if not line.strip():
                        continue
                    try:
                        finding = json.loads(line)
                        if not isinstance(finding, dict) or not finding.get("template-id"):
                            raise ValueError("missing template-id")
                        report["findings"].append(finding)
                    except (ValueError, TypeError):
                        stage["status"] = "error"
                        report["diagnostics"].append(f"Invalid JSONL finding in {findings.name}")
        incomplete = any(s["status"] == "error" for s in report["stages"]) or bool(report.get("crawl", {}).get("diagnostics")) or report.get("crawl", {}).get("limited", False)
        report["status"] = "planned" if args.dry_run else "incomplete" if incomplete else "completed"
        exit_code = 2 if incomplete else 1 if report["findings"] else 0
    except (OSError, ValueError) as error:
        report["diagnostics"].append(str(error))
        print(f"[-] {error}", file=sys.stderr)
    except KeyboardInterrupt:
        report["diagnostics"].append("Interrupted; results are partial")
        exit_code = 130
    finally:
        write_report(output, report)
        print(f"[+] Web assessment report: {output / 'report.md'}")
    return exit_code


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--_fetch":
        try:
            print(json.dumps(fetch_worker(normalize_url(sys.argv[2]), float(sys.argv[3]), sys.argv[4] == "1")))
        except (OSError, ValueError, urllib.error.URLError) as error:
            print(str(error), file=sys.stderr)
            sys.exit(2)
    else:
        sys.exit(main())
