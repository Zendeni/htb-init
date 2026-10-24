#!/usr/bin/env python3
"""Bounded web assessment for HTB workspaces; Python 3.10+, no Python dependencies.

Nuclei and a local nuclei-templates checkout are required for active assessment.
Dry runs validate scope and save a plan without network access or subprocesses.
"""
from __future__ import annotations

import argparse
import base64
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


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
    "DAST uses complete captured and discovered requests, including query/path/header/cookie and POST/JSON/XML bodies where the selected templates support them. Template selection does not prove each input was exercised.",
    "Crawler follows seeded origins and query navigation without submitting forms or rendering JavaScript. Valid form requests are submitted by the active DAST stage; incomplete forms require a captured request.",
    "Sessions are isolated by exact origin. Captured request headers override session defaults. Tokens are not automatically refreshed during Nuclei fuzzing; expired sessions need renewed captures.",
    "The known HTTP template stage is unauthenticated; origin-scoped session credentials are carried by the complete DAST requests.",
    "Collector curl --resolve mappings are not inherited by Nuclei. Approved aliases must resolve locally; unresolved origins are blocked and reported as incomplete.",
    "Nuclei templates are trusted scanner code; target filtering and disabled redirects are not a network sandbox.",
]
GENERIC_WEB_EXCLUDED_PORTS = {5985, 5986}  # WinRM is handled by dedicated service enumeration.


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


def is_generic_web_candidate(url, workspace):
    parsed = urllib.parse.urlsplit(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in GENERIC_WEB_EXCLUDED_PORTS:
        return True

    # Ports 5985/5986 conventionally expose WinRM, but a real web application
    # can legitimately listen there. Only suppress an automatically discovered
    # URL when Nmap's service evidence identifies WinRM/Microsoft HTTPAPI.
    services = workspace / "scans" / "tcp-services.txt"
    if not services.is_file():
        return True
    for line in services.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r"^\s*(\d+)/tcp\s+open\s+(\S+)(?:\s+(.*))?$", line)
        if not match or int(match.group(1)) != port:
            continue
        service = match.group(2).lower()
        details = (match.group(3) or "").lower()
        return not (
            service in {"winrm", "wsman", "ssl/winrm", "ssl/wsman"}
            or "microsoft httpapi" in details
        )
    return True


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


def private_write(path, text):
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


def validated_headers(value, url=None):
    if not isinstance(value, dict):
        raise ValueError("Headers must be an object of string names and values")
    result = {}
    for key, item in value.items():
        if not isinstance(key, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
            raise ValueError("Invalid HTTP header name")
        if not isinstance(item, str) or any(ord(c) < 32 or ord(c) == 127 for c in item):
            raise ValueError(f"Invalid value for HTTP header {key}")
        low = key.lower()
        if low in result:
            raise ValueError(f"Duplicate HTTP header: {key}")
        if low == "host":
            if not url or normalize_url(urllib.parse.urlsplit(url).scheme + "://" + item + "/") != origin(url) + "/":
                raise ValueError("Captured Host header differs from the request URL")
            continue
        if low == "transfer-encoding":
            raise ValueError("Chunked captures must be decoded before import")
        if low in ("content-length", "connection", "proxy-connection"):
            continue
        result[low] = item
    return result


COOKIE_FIELDS = ("version", "name", "value", "port", "port_specified", "domain", "domain_specified", "domain_initial_dot", "path", "path_specified", "secure", "expires", "discard", "comment", "comment_url", "rfc2109")


def cookie_dict(cookie):
    return dict({key: getattr(cookie, key) for key in COOKIE_FIELDS}, rest=cookie._rest)


def cookie_jar(values):
    jar = http.cookiejar.CookieJar()
    for value in values:
        jar.set_cookie(http.cookiejar.Cookie(**value))
    return jar


class Sessions:
    """Cookie jars and explicit headers never cross an origin boundary."""
    def __init__(self, path=None, scope=None):
        self.origins = {}
        if not path:
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("origins"), dict):
            raise ValueError("Session file must contain an origins object")
        for key, value in data["origins"].items():
            url = normalize_url(key)
            if url != origin(url) + "/" or not scope.allows(url):
                raise ValueError(f"Session origin is invalid or outside scope: {key}")
            if not isinstance(value, dict):
                raise ValueError("Each session origin must be an object")
            headers = validated_headers(value.get("headers", {}))
            if "cookie" in headers:
                raise ValueError("Use the session cookies object instead of a Cookie header")
            cookies = value.get("cookies", {})
            if not isinstance(cookies, dict):
                raise ValueError("Session cookies must be an object")
            state = {"headers": headers, "cookies": []}
            for name, item in cookies.items():
                if not isinstance(name, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or not isinstance(item, str) or any(ord(c) < 33 or ord(c) == 127 or c in ';,' for c in item):
                    raise ValueError("Invalid session cookie")
                cookie = http.cookiejar.Cookie(0, name, item, None, False, urllib.parse.urlsplit(url).hostname, False, False, "/", True, url.startswith("https:"), None, True, None, None, {})
                state["cookies"].append(cookie_dict(cookie))
            self.origins[origin(url)] = state

    def state(self, url):
        return self.origins.setdefault(origin(url), {"headers": {}, "cookies": []})

    def headers(self, url):
        state = self.state(url)
        request = urllib.request.Request(url, headers=state["headers"])
        cookie_jar(state["cookies"]).add_cookie_header(request)
        return {key.lower(): value for key, value in request.header_items()}


def request_record(method, url, headers, body=b"", source="capture"):
    if not isinstance(method, str) or not re.fullmatch(r"[A-Za-z]+", method):
        raise ValueError("Invalid captured HTTP method")
    method = method.upper()
    if method in ("CONNECT", "TRACE"):
        raise ValueError(f"Unsupported captured HTTP method: {method}")
    return {"method": method, "url": normalize_url(url), "headers": validated_headers(headers, normalize_url(url)), "body": body, "source": source}


def load_requests(paths, scope):
    requests = []
    for path in paths:
        content = path.read_bytes()
        if len(content) > 20 * 1024 * 1024:
            raise ValueError("Capture file exceeds 20 MiB")
        if content.lstrip().startswith(b"<"):
            if b"<!ENTITY" in content.upper() or re.search(br"<!DOCTYPE\s+[^>\[]*\b(?:SYSTEM|PUBLIC)\b", content, re.I):
                raise ValueError("Burp XML entities and external DTDs are not supported")
            try:
                document = ET.fromstring(content)
            except ET.ParseError as error:
                raise ValueError(f"Invalid Burp XML: {error}") from error
            if document.tag != "items":
                raise ValueError("Expected a Burp items XML document")
            for item in document.findall("item"):
                url = normalize_url(item.findtext("url", ""))
                element = item.find("request")
                if element is None or not element.text:
                    raise ValueError("Burp item has no request")
                raw = base64.b64decode(element.text, validate=True) if element.get("base64") == "true" else element.text.encode("utf-8")
                separator = b"\r\n\r\n" if b"\r\n\r\n" in raw else b"\n\n"
                head, marker, body = raw.partition(separator)
                lines = head.decode("iso-8859-1").splitlines()
                if not marker or not lines:
                    raise ValueError("Invalid raw Burp request")
                parts = lines.pop(0).split(" ")
                parsed = urllib.parse.urlsplit(url)
                target = urllib.parse.urlunsplit(("", "", parsed.path, parsed.query, ""))
                if len(parts) != 3 or parts[1] not in (target, url) or parts[2] not in ("HTTP/1.0", "HTTP/1.1", "HTTP/2"):
                    raise ValueError("Burp request line and URL disagree")
                headers = {}
                for line in lines:
                    key, sep, value = line.partition(":")
                    if not sep or key.lower() in headers:
                        raise ValueError("Invalid or duplicate header in Burp request")
                    headers[key.lower()] = value.strip()
                requests.append(request_record(parts[0], url, headers, body, "burp"))
        else:
            data = json.loads(content)
            records = data.get("requests") if isinstance(data, dict) else data
            if not isinstance(records, list):
                raise ValueError("Capture JSON must contain a requests array")
            for item in records:
                if not isinstance(item, dict) or not isinstance(item.get("url"), str):
                    raise ValueError("Each captured request needs a URL")
                if "body" in item and "body_base64" in item:
                    raise ValueError("Use body or body_base64, not both")
                if not isinstance(item.get("body", ""), str):
                    raise ValueError("Captured body must be a string; use body_base64 for binary")
                body = base64.b64decode(item["body_base64"], validate=True) if "body_base64" in item else item.get("body", "").encode("utf-8")
                requests.append(request_record(item.get("method", "GET"), item["url"], item.get("headers", {}), body))
    for request in requests:
        if not scope.allows(request["url"]):
            raise ValueError(f"Captured request is outside scope: {request['url']}")
    return requests


def export_burp(path, requests, sessions):
    document = ET.Element("items", {"burpVersion": "htb-init", "exportTime": datetime.now(timezone.utc).isoformat()})
    for request in requests:
        url = request["url"]
        parsed = urllib.parse.urlsplit(url)
        headers = dict(sessions.headers(url), **request["headers"])
        target = urllib.parse.urlunsplit(("", "", parsed.path, parsed.query, ""))
        raw = f"{request['method']} {target} HTTP/1.1\r\nHost: {parsed.netloc}\r\n"
        raw += "".join(f"{key}: {value}\r\n" for key, value in headers.items())
        raw += f"Content-Length: {len(request['body'])}\r\n\r\n"
        item = ET.SubElement(document, "item")
        for name, value in (("url", url), ("host", parsed.hostname), ("port", parsed.port or (443 if parsed.scheme == "https" else 80)), ("protocol", parsed.scheme), ("method", request["method"]), ("path", target), ("status", "0")):
            ET.SubElement(item, name).text = str(value)
        ET.SubElement(item, "request", {"base64": "true"}).text = base64.b64encode(raw.encode("utf-8") + request["body"]).decode("ascii")
        ET.SubElement(item, "response", {"base64": "true"}).text = ""
    private_write(path, ET.tostring(document, encoding="unicode", xml_declaration=True))


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []
        self.forms = []
        self.form = None
        self.control = None
        self.option = None
        self.base = None

    def field(self, attrs, value):
        if not self.form or not attrs.get("name") or "disabled" in attrs:
            return
        if "required" in attrs and not value:
            self.form["issues"].append(f"Required field {attrs['name']} has no value; supply a captured request")
        self.form["fields"].append((attrs["name"], value))

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "base" and self.base is None:
            self.base = attrs.get("href")
        if tag in ("a", "iframe") and attrs.get("href" if tag == "a" else "src"):
            self.urls.append(attrs["href" if tag == "a" else "src"])
        if tag == "form":
            self.form = {"action": attrs.get("action", ""), "method": attrs.get("method", "get").lower(), "enctype": attrs.get("enctype", "application/x-www-form-urlencoded").lower(), "fields": [], "issues": [], "required": []}
        if not self.form:
            return
        if attrs.get("form") or (tag == "fieldset" and "disabled" in attrs):
            self.form["issues"].append("External form controls/disabled fieldsets require a captured request")
        if tag in ("input", "textarea", "select") and "required" in attrs and "disabled" not in attrs and attrs.get("name"):
            self.form["required"].append(attrs["name"])
        if tag == "input" and "disabled" not in attrs:
            kind = attrs.get("type", "text").lower()
            if kind in ("file", "image"):
                self.form["issues"].append(f"{kind} control requires a captured request")
            elif kind in ("submit", "button", "reset"):
                if attrs.get("name") or attrs.get("formaction") or attrs.get("formmethod"):
                    self.form["issues"].append("Submit-button choice requires a captured request")
            elif kind not in ("checkbox", "radio") or "checked" in attrs:
                self.field(attrs, attrs.get("value", "on" if kind in ("checkbox", "radio") else ""))
        if tag == "button" and (attrs.get("name") or attrs.get("formaction") or attrs.get("formmethod")):
            self.form["issues"].append("Submit-button choice requires a captured request")
        if tag in ("textarea", "select"):
            self.control = {"tag": tag, "attrs": attrs, "text": "", "options": []}
        if tag == "option" and self.control and self.control["tag"] == "select":
            if self.option:
                self.control["options"].append(self.option)
            self.option = {"attrs": attrs, "text": ""}

    def handle_data(self, data):
        if self.option:
            self.option["text"] += data
        elif self.control:
            self.control["text"] += data

    def handle_endtag(self, tag):
        if tag == "option" and self.option and self.control:
            self.control["options"].append(self.option)
            self.option = None
        if self.control and tag == self.control["tag"]:
            control = self.control
            if tag == "textarea":
                self.field(control["attrs"], control["text"].replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n"))
            else:
                if self.option:
                    control["options"].append(self.option)
                    self.option = None
                options = [x for x in control["options"] if "disabled" not in x["attrs"]]
                selected = [x for x in options if "selected" in x["attrs"]]
                if "multiple" not in control["attrs"]:
                    selected = selected[-1:] or options[:1]
                for item in selected:
                    self.field(control["attrs"], item["attrs"].get("value", item["text"].strip()))
                if not selected and "required" in control["attrs"]:
                    self.form["issues"].append("Required selection is empty; supply a captured request")
            self.control = None
        if tag == "form" and self.form is not None:
            present = {key for key, value in self.form["fields"] if value}
            for name in self.form["required"]:
                if name not in present:
                    self.form["issues"].append(f"Required field {name} has no usable value")
            self.forms.append(self.form)
            self.form = None


def form_request(form, page, base):
    if form["issues"]:
        return None, "; ".join(form["issues"])
    url = normalize_url(urllib.parse.urljoin(base, form["action"]) if form["action"] else page)
    method = form["method"].upper()
    if method not in ("GET", "POST"):
        return None, "Unsupported form method; supply a captured request"
    fields = urllib.parse.urlencode(form["fields"])
    if method == "GET":
        parsed = urllib.parse.urlsplit(url)
        url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, fields, ""))
        return request_record(method, url, {"Referer": page}, source="form"), None
    if form["enctype"] != "application/x-www-form-urlencoded":
        return None, "Multipart/text form needs an exact captured request"
    return request_record(method, url, {"Content-Type": form["enctype"], "Referer": page}, fields.encode("utf-8"), "form"), None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_worker(url, timeout, insecure, state=None, method="GET", body=None):
    """One bounded-size HTTP response. Parent kills this process at its deadline."""
    context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    state = state or {"headers": {}, "cookies": []}
    jar = cookie_jar(state["cookies"])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor(jar))
    request = urllib.request.Request(url, headers=dict({"User-Agent": "htb-init-web-assess/1.0"}, **state["headers"]), data=body, method=method)
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read(1024 * 1024 + 1) if "text/html" in response.headers.get("Content-Type", "").lower() else b""
        return {"status": response.status, "headers": dict(response.headers), "body": body[:1024 * 1024].decode("utf-8", errors="replace"), "truncated": len(body) > 1024 * 1024, "cookies": [cookie_dict(c) for c in jar], "request_headers": dict(request.header_items())}


def fetch_page(url, args, remaining, request=None):
    # Socket timeouts alone cannot stop a server that continually trickles bytes.
    # A subprocess deadline bounds connection, headers AND body and leaves no
    # background request thread behind after timeout.
    if not hasattr(args, "sessions"):
        args.sessions = Sessions()
    payload = {"url": url, "timeout": args.request_timeout, "insecure": args.insecure, "state": args.sessions.state(url)}
    if request:
        payload["state"] = dict(payload["state"], headers=dict(payload["state"]["headers"], **request["headers"]))
        payload.update(method=request["method"], body_base64=base64.b64encode(request["body"]).decode("ascii"))
    result = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--_fetch"], input=json.dumps(payload),
                            capture_output=True, text=True, encoding="utf-8",
                            timeout=min(args.request_timeout, remaining), check=False)
    if result.returncode:
        raise ValueError(result.stderr.strip() or "HTTP fetch failed")
    response = json.loads(result.stdout)
    args.sessions.state(url)["cookies"] = response.get("cookies", [])
    return response


def crawl(urls, scope, args):
    if not hasattr(args, "sessions"):
        args.sessions = Sessions()
    if not hasattr(args, "discovered_requests"):
        args.discovered_requests = []
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
            if response["status"] in (401, 403):
                diagnostics.append(f"Authentication/access check failed: HTTP {response['status']} at {url}; renew the session or inspect access rules")
            elif response["status"] >= 500:
                diagnostics.append(f"Server returned HTTP {response['status']} at {url}; input discovery may be incomplete")
            args.discovered_requests.append(request_record("GET", url, args.sessions.headers(url), source="navigation"))
            headers = {k.lower(): v for k, v in response["headers"].items()}
            location = headers.get("location")
            if location and 300 <= response["status"] < 400:
                try:
                    redirect = normalize_url(urllib.parse.urljoin(url, location))
                    if origin(redirect) not in allowed_origins or not scope.allows(redirect):
                        diagnostics.append(f"Blocked redirect from {url} to {redirect}; seed an explicitly scoped destination origin to assess it")
                    else:
                        found.append(location)
                    if re.search(r"/(?:login|signin|sign-in)(?:[/?#]|$)", redirect, re.I):
                        diagnostics.append(f"Login redirect at {url}; authenticated coverage requires a current session")
                except ValueError:
                    diagnostics.append(f"Invalid redirect at {url}")
            limited = limited or response.get("truncated", False)
            if "text/html" in headers.get("content-type", "").lower():
                parser = Links()
                parser.feed(response["body"])
                base = urllib.parse.urljoin(url, parser.base) if parser.base else url
                found.extend(urllib.parse.urljoin(base, link) for link in parser.urls)
                for form in parser.forms:
                    summary = {"page": url, "action": form["action"], "method": form["method"], "field_names": [x[0] for x in form["fields"]]}
                    record, reason = form_request(form, url, base)
                    if record and (origin(record["url"]) not in allowed_origins or not scope.allows(record["url"])):
                        record, reason = None, "Form action is outside the seeded, included origins"
                    if record and len(args.discovered_requests) >= args.max_endpoints:
                        record, reason = None, "Form request limit reached"
                        limited = True
                    if record:
                        record["headers"] = dict(args.sessions.headers(record["url"]), **record["headers"])
                        args.discovered_requests.append(record)
                        summary["status"] = "prepared"
                    else:
                        summary.update(status="untested", reason=reason)
                        diagnostics.append(f"Untested form at {url}: {reason}")
                    forms.append(summary)
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
                # Navigation links can contain queries. Synthesized form requests
                # are kept separately and are never submitted by the crawler.
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
    parser.add_argument("--session-file", type=Path, help="JSON sessions keyed by exact origin; headers/cookies never cross origins")
    parser.add_argument("--requests-file", type=Path, action="append", default=[], help="complete request captures: structured JSON or Burp XML (repeatable)")
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
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, timeout=timeout, env=env, check=False)
            return result.returncode
        except subprocess.TimeoutExpired:
            output.write("\nAssessment stage exceeded its timeout.\n")
            return 124
        except OSError as error:
            output.write(str(error))
            return 127


def assess_stage(name, targets, template_dir, args, output, config, state=None, checkpoint=None):
    prefix = output / name
    findings = prefix.with_suffix(".jsonl")
    templates = prefix.with_suffix(".templates.txt")
    select = [args.nuclei, "-config", str(config), "-t", str(template_dir), "-pt", "http", "-dut", "-dr", "-duc", "-nc", "-no-stdin", "-etags", "dos,bruteforce,fuzz,headless"]
    if not args.oast:
        select.append("-ni")
    if name == "dast":
        # -dast is required; ordinary scans do not load DAST templates.
        select += ["-dast", "-fa", "low"]
        select[select.index("dos,bruteforce,fuzz,headless")] = "dos,bruteforce,headless"
    error_log = prefix.with_suffix(".errors.jsonl")
    command = select + ["-l", str(targets)]
    if name == "dast":
        command += ["-im", "burp"]
    command += ["-rl", str(args.rate_limit), "-c", str(args.concurrency), "-bs", "1", "-timeout", str(args.request_timeout), "-retries", "0", "-jsonl", "-o", str(findings), "-elog", str(error_log), "-sj", "-si", "1"]
    result = state if state is not None else {}
    result.update(name=name, status="planned", command=command, findings_file=str(findings), error_file=str(error_log))
    if args.dry_run:
        return result
    if not template_dir.is_dir():
        return dict(result, status="error", error=f"Missing local template directory: {template_dir}; install/update nuclei-templates first")
    # Inventory with identical filters; an empty template set must never look clean.
    result.update(status="running", phase="inventory")
    if checkpoint:
        checkpoint()
    code = run_command(select + ["-tl", "-silent"], templates, min(args.scan_timeout, 60))
    selected = [line for line in templates.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip().endswith((".yaml", ".yml"))]
    result["template_count"] = len(selected)
    if code or not selected:
        return dict(result, status="error", returncode=code, error="Template inventory failed or selected zero templates; inspect stage log")
    findings.touch()
    findings.chmod(0o600)
    result["phase"] = "scan"
    if checkpoint:
        checkpoint()
    code = run_command(command, prefix.with_suffix(".log"), args.scan_timeout)
    result.update(status="completed" if code == 0 else "error", returncode=code)
    errors = error_log.read_text(encoding="utf-8", errors="replace").splitlines() if error_log.exists() else []
    result["request_errors"] = sum(bool(line.strip()) for line in errors)
    log_text = prefix.with_suffix(".log").read_text(encoding="utf-8", errors="replace")
    for line in log_text.splitlines():
        try:
            stats = json.loads(line)
            if isinstance(stats, dict) and "requests" in stats and "errors" in stats:
                result["statistics"] = stats
        except ValueError:
            pass
    stats = result.get("statistics", {})
    try:
        has_errors = int(stats.get("errors", 0)) > 0
    except (TypeError, ValueError):
        has_errors = True
    if result["request_errors"] or has_errors or re.search(r"\[(?:ERR|FTL)\]", log_text):
        result.update(status="error", error="Scanner reported request/runtime errors; inspect the error file and stage log")
    if stats and str(stats.get("requests")) == "0":
        result.update(status="error", error="No scanner requests were executed; selected templates may not apply to these inputs")
    for path in (error_log, templates, prefix.with_suffix(".log")):
        if path.exists():
            path.chmod(0o600)
    return result


def preflight(urls, args):
    """Prove each origin reachable even with --no-crawl; retain per-origin status."""
    results = []
    for base in sorted({origin(url) for url in urls}):
        try:
            response = fetch_page(base + "/", args, args.request_timeout)
            status = response["status"]
            item = {"origin": base, "reachable": True, "status": status}
            if status in (401, 403):
                item["error"] = f"HTTP {status}: session/authentication or access rules blocked the origin"
            elif status >= 500:
                item["error"] = f"HTTP {status}: server failure may invalidate input tests"
            results.append(item)
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            results.append({"origin": base, "reachable": False, "error": str(error)})
    return results


def check_request_baselines(requests, args):
    """Validate exact supplied/form requests before their inputs are mutated."""
    results = []
    deadline = time.monotonic() + args.crawl_timeout
    for request in requests:
        if request["source"] not in ("capture", "burp", "form"):
            continue
        item = {"url": request["url"], "method": request["method"], "source": request["source"]}
        if time.monotonic() >= deadline:
            results.append(dict(item, error="Request baseline budget exhausted; request was not validated"))
            continue
        try:
            response = fetch_page(request["url"], args, max(0.1, deadline - time.monotonic()), request)
            item["status"] = response["status"]
            headers = {key.lower(): value for key, value in response["headers"].items()}
            if response["status"] >= 400:
                item["error"] = f"Baseline HTTP {response['status']}: renew authentication or supply a valid request before interpreting negative input tests"
            elif 300 <= response["status"] < 400:
                location = urllib.parse.urljoin(request["url"], headers.get("location", ""))
                if origin(location) != origin(request["url"]):
                    item["error"] = "Baseline redirect leaves the captured origin; destination requires a separately scoped request"
                elif re.search(r"/(?:login|signin|sign-in)(?:[/?#]|$)", location, re.I):
                    item["error"] = "Baseline redirects to login; session appears expired"
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            item["error"] = str(error)
        results.append(item)
        time.sleep(min(1 / args.rate_limit, max(0, deadline - time.monotonic())))
    return results


class AssessmentInterrupted(Exception):
    def __init__(self, signum):
        self.signum = signum


def interrupt_handler(signum, frame):
    raise AssessmentInterrupted(signum)


def atomic_write(path, value):
    descriptor, name = tempfile.mkstemp(prefix=path.name + ".tmp-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(value)
        temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_report(output, report):
    atomic_write(output / "report.json", json.dumps(report, indent=2) + "\n")
    lines = ["# Web assessment", "", f"Status: **{report['status']}**", "", f"Findings: {len(report['findings'])}", "", f"Blind OAST checks enabled: {report['oast_enabled']}", "", "## Stages", ""]
    for stage in report["stages"]:
        detail = stage.get("error") or stage.get("reason")
        lines.append(f"- {stage['name']}: {stage['status']}" + (f" — {detail}" if detail else ""))
    if report.get("crawl"):
        lines += ["", f"Crawl: {report['crawl']['visited']} pages visited; truncated by limits: {report['crawl']['limited']}."]
    if report.get("request_coverage"):
        coverage = report["request_coverage"]
        lines += ["", "## Input coverage", "", f"Prepared requests: {coverage['total']}; methods: {coverage['methods']}; body types: {coverage['body_types']}.", "", "Prepared input is not a confirmed vulnerability or proof every template exercised it. Raw request bodies, cookies, and authorization headers are in the restricted request artifact, not this overview."]
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
    atomic_write(output / "report.md", "\n".join(lines))


def collect_findings(report, stage):
    if not stage.get("findings_file"):
        return
    path = Path(stage["findings_file"])
    if not path.is_file():
        return
    existing = {(item.get("evidence_file"), item.get("evidence_line")) for item in report["findings"]}
    for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if (str(path), number) in existing:
            continue
        if not line.strip():
            continue
        try:
            finding = json.loads(line)
            if not isinstance(finding, dict) or not finding.get("template-id"):
                raise ValueError("missing template-id")
            # Raw HTTP includes credentials. Keep it in mode-0600 JSONL only.
            finding = {key: value for key, value in finding.items() if key not in ("request", "response", "curl-command")}
            finding.update(evidence_file=str(path), evidence_line=number)
            report["findings"].append(finding)
        except (ValueError, TypeError):
            stage["status"] = "error"
            report["diagnostics"].append(f"Invalid JSONL finding in {path.name}")


def prepare_corpus(captured, endpoints, args):
    requests, seen = [], set()
    for request in captured + args.discovered_requests + [request_record("GET", url, {}, source="seed") for url in endpoints]:
        key = (request["method"], request["url"], request["body"], tuple(sorted(request["headers"].items())))
        if key not in seen:
            seen.add(key)
            requests.append(request)
    if len(requests) > args.max_endpoints:
        raise ValueError("Complete request corpus exceeds --max-endpoints; split captures or raise the limit")
    return requests


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
    report = {"schema_version": 2, "status": "incomplete", "targets": [], "stages": [], "findings": [], "diagnostics": [], "limits": list(LIMITS), "manual_review": MANUAL, "oast_enabled": args.oast}
    if not args.oast:
        report["limits"].append("OAST is disabled: blind callback-based SSRF/XXE templates are excluded. Enable --oast to include them.")
        report["limits"].append("A template containing OAST payloads can be excluded entirely, including its in-band XXE payloads. An XML request alone does not establish XXE coverage; inspect selected templates and execution evidence.")
    exit_code = 2
    previous_sigterm = signal.signal(signal.SIGTERM, interrupt_handler)
    write_report(output, report)
    atomic_write(parent / "latest.json", json.dumps({"run_id": output.name}) + "\n")
    try:
        scope = Scope(args.workspace, args.allow_host)
        args.sessions = Sessions(args.session_file, scope)
        args.discovered_requests = []
        captured = load_requests(args.requests_file, scope)
        explicit = list(args.url)
        if args.urls_file:
            explicit += [line.strip() for line in args.urls_file.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
        candidates = [(u, True) for u in explicit + [request["url"] for request in captured]]
        if not candidates:
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
                if not strict and not is_generic_web_candidate(url, args.workspace):
                    report["diagnostics"].append(
                        f"Skipped discovered target {value!r}: standard WinRM ports are handled by dedicated service enumeration"
                    )
                    continue
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
        if not args.dry_run:
            report["preflight"] = preflight(endpoints, args)
            for item in report["preflight"]:
                if item.get("error"):
                    report["diagnostics"].append(f"Preflight {item['origin']}: {item['error']}")
            reachable = {item["origin"] for item in report["preflight"] if item["reachable"]}
            endpoints = [url for url in endpoints if origin(url) in reachable]
            captured = [request for request in captured if origin(request["url"]) in reachable]
            write_report(output, report)
            if not endpoints:
                raise ValueError("No reachable target origins; resolve approved lab aliases and retry")
        if not args.no_crawl and not args.dry_run:
            endpoints, report["crawl"] = crawl(endpoints, scope, args)
            report["diagnostics"] += report["crawl"]["diagnostics"]
            if report["crawl"]["limited"]:
                report["diagnostics"].append("Crawl truncated by page, endpoint, response-size or time limits; discovery is partial.")
        report["endpoints"] = endpoints
        config = output / "nuclei-config.yaml"
        private_write(config, "{}\n")
        target_file = output / "targets.txt"
        private_write(target_file, "\n".join(endpoints) + "\n")
        stages = [("http", target_file, args.templates / "http")]
        corpus = prepare_corpus(captured, endpoints, args)
        request_file = output / "requests.burp.xml"
        export_burp(request_file, corpus, args.sessions)
        report["request_coverage"] = {"total": len(corpus), "methods": sorted({request["method"] for request in corpus}), "body_types": sorted({request["headers"].get("content-type", "unspecified").split(";", 1)[0] for request in corpus if request["body"]}), "artifact": str(request_file), "sources": {source: sum(request["source"] == source for request in corpus) for source in sorted({request["source"] for request in corpus})}}
        report["session_origins"] = sorted(args.sessions.origins)
        if not args.dry_run and not args.no_dast:
            write_report(output, report)
            report["request_checks"] = check_request_baselines(corpus, args)
            for item in report["request_checks"]:
                if item.get("error"):
                    report["diagnostics"].append(f"Request {item['method']} {item['url']}: {item['error']}")
            # Baseline responses can rotate session cookies; export the current jar.
            export_burp(request_file, corpus, args.sessions)
        if args.no_dast:
            report["stages"].append({"name": "dast", "status": "skipped", "reason": "disabled"})
        else:
            stages.append(("dast", request_file, args.templates / "dast"))
        for name, inputs, templates in stages:
            print(f"[+] Web assessment: {name}", flush=True)
            stage = {"name": name, "status": "running"}
            report["stages"].append(stage)
            result = assess_stage(name, inputs, templates, args, output, config, stage, lambda: write_report(output, report))
            stage.update(result)
            collect_findings(report, stage)
            write_report(output, report)
        incomplete = any(s["status"] == "error" for s in report["stages"]) or bool(report.get("crawl", {}).get("diagnostics")) or report.get("crawl", {}).get("limited", False) or any(item.get("error") for item in report.get("preflight", [])) or any(item.get("error") for item in report.get("request_checks", []))
        report["status"] = "planned" if args.dry_run else "incomplete" if incomplete else "completed"
        exit_code = 2 if incomplete else 1 if report["findings"] else 0
    except (OSError, ValueError) as error:
        report["diagnostics"].append(str(error))
        print(f"[-] {error}", file=sys.stderr)
    except (KeyboardInterrupt, AssessmentInterrupted) as error:
        report["diagnostics"].append("Interrupted; results are partial")
        exit_code = 128 + error.signum if isinstance(error, AssessmentInterrupted) else 130
        report["status"] = "incomplete"
        for stage in report["stages"]:
            collect_findings(report, stage)
            if stage["status"] == "running":
                stage.update(status="error", error="Interrupted during " + stage.get("phase", "setup"))
    finally:
        write_report(output, report)
        signal.signal(signal.SIGTERM, previous_sigterm)
        print(f"[+] Web assessment report: {output / 'report.md'}")
    return exit_code


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--_fetch":
        try:
            payload = json.load(sys.stdin)
            body = base64.b64decode(payload["body_base64"], validate=True) if "body_base64" in payload else None
            print(json.dumps(fetch_worker(normalize_url(payload["url"]), float(payload["timeout"]), payload["insecure"], payload["state"], payload.get("method", "GET"), body)))
        except (OSError, ValueError, urllib.error.URLError) as error:
            print(str(error), file=sys.stderr)
            sys.exit(2)
    else:
        sys.exit(main())
