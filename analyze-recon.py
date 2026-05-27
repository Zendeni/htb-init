#!/usr/bin/env python3
"""
analyze-recon.py

Offline recon analyzer for htb-init workspaces and recon ZIP archives.

Purpose:
- Parse raw recon output collected by htb-init/recon.sh.
- Generate a practical recon-analysis.md with technologies, endpoints,
  auth clues, exposed services, likely attack paths, and manual next steps.
- Work on both extracted workspace folders and zip-recon.sh ZIP archives.
- Use only Python standard library.

Usage:
  python3 analyze-recon.py /home/zendeni/htb_labs/principal
  python3 analyze-recon.py /home/zendeni/htb_labs/principal/principal-recon-*.zip
  python3 analyze-recon.py <target> -o /tmp/recon-analysis.md

Design notes:
- This script is a hint engine, not an exploit oracle.
- Findings are suggestions for manual verification.
- No network requests are made.
"""

from __future__ import annotations

import argparse
import html
import os
import re
import shutil
import sys
import tempfile
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
API_PATH_RE = re.compile(
    r"""(?:"|')((?:/[A-Za-z0-9._~!$&'()*+,;=:@%-]+){1,})(?:"|')"""
)
FETCH_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|XMLHttpRequest|open)\s*\(?\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
FORM_ACTION_RE = re.compile(r"""<form[^>]+action=["']?([^"'\s>]+)""", re.IGNORECASE)
INPUT_RE = re.compile(r"""<input[^>]+(?:name|id)=["']?([^"'\s>]+)""", re.IGNORECASE)
SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)
LINK_HREF_RE = re.compile(r"""<a[^>]+href=["']([^"']+)["']""", re.IGNORECASE)
PORT_TABLE_RE = re.compile(r"^\|\s*(\d+)\s*\|\s*([^\n|]+?)\s*\|\s*([^\n|]*?)\s*\|", re.MULTILINE)
NMAP_OPEN_RE = re.compile(r"^(\d+)/(tcp|udp)[^\S\r\n]+open[^\S\r\n]+(\S+)(?:[^\S\r\n]+([^\r\n]*))?$", re.MULTILINE)
HOST_LINE_RE = re.compile(r"^\s*HOST=\"?([^\"\n]+)\"?\s*$", re.MULTILINE)
IP_LINE_RE = re.compile(r"^\s*IP=\"?([^\"\n]+)\"?\s*$", re.MULTILINE)
BOX_LINE_RE = re.compile(r"^\s*BOX=\"?([^\"\n]+)\"?\s*$", re.MULTILINE)

NEXT_WINDOW_RE = re.compile(
    r"""window\.next\s*=\s*\{[^}]*?version\s*:\s*["']([^"']+)["'][^}]*?\}""",
    re.IGNORECASE | re.DOTALL,
)
NEXT_VERSION_RE = re.compile(
    r"""(?:Next\.js|next)["'\s:=/_-]{0,12}(?:version)?["'\s:=/_-]{0,12}(1[0-6]\.[0-9][0-9A-Za-z.\-]*)""",
    re.IGNORECASE,
)
REACT_VERSION_RE = re.compile(
    r"""(?:React|react)["'\s:=/_-]{0,12}(?:version)?["'\s:=/_-]{0,12}(1[789]\.[0-9][0-9A-Za-z.\-]*)""",
    re.IGNORECASE,
)
NEXT_STATIC_RE = re.compile(r"""(?:src|href)=["']([^"']*/_next/static/[^"']+)["']""", re.IGNORECASE)
HTTP_HEADER_RE = re.compile(r"""^([A-Za-z0-9-]+):\s*(.+)$""", re.MULTILINE)



@dataclass
class Port:
    number: int
    service: str = ""
    version: str = ""
    proto: str = "tcp"


@dataclass
class Finding:
    title: str
    detail: str
    confidence: str = "medium"
    evidence: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)


@dataclass
class ReconData:
    root: Path
    source: Path
    box: str = ""
    ip: str = ""
    host: str = ""
    ports: dict[int, Port] = field(default_factory=dict)
    files: dict[str, str] = field(default_factory=dict)
    web_urls: set[str] = field(default_factory=set)
    technologies: set[str] = field(default_factory=set)
    endpoints: set[str] = field(default_factory=set)
    js_files: set[str] = field(default_factory=set)
    nextjs_versions: set[str] = field(default_factory=set)
    react_versions: set[str] = field(default_factory=set)
    nextjs_app_router: bool = False
    rsc_indicators: set[str] = field(default_factory=set)
    http_headers: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    nikto_likely_false_positives: list[str] = field(default_factory=list)
    forms: set[str] = field(default_factory=set)
    inputs: set[str] = field(default_factory=set)
    smb_shares: set[str] = field(default_factory=set)
    domain: str = ""
    computer: str = ""
    naming_contexts: set[str] = field(default_factory=set)
    interesting_lines: list[str] = field(default_factory=list)


def strip_ansi(s: str) -> str:
    s = ANSI_RE.sub("", s)
    s = CONTROL_RE.sub("", s)
    return s


def read_text(path: Path, max_bytes: int = 2_000_000) -> str:
    try:
        data = path.read_bytes()
    except Exception:
        return ""
    if len(data) > max_bytes:
        data = data[:max_bytes]
    return strip_ansi(data.decode("utf-8", errors="ignore"))


def safe_extract_zip(zip_path: Path, dest: Path) -> None:
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.infolist():
            name = member.filename
            if not name or name.endswith("/"):
                continue

            # Basic zip-slip protection.
            target = (dest / name).resolve()
            if not str(target).startswith(str(dest.resolve()) + os.sep):
                raise RuntimeError(f"Unsafe zip entry blocked: {name}")

            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst)


def materialize_input(src: Path) -> tuple[Path, Optional[tempfile.TemporaryDirectory]]:
    src = src.expanduser().resolve()
    if not src.exists():
        raise FileNotFoundError(src)

    if src.is_dir():
        return src, None

    if zipfile.is_zipfile(src):
        tmp = tempfile.TemporaryDirectory(prefix="analyze-recon-")
        root = Path(tmp.name)
        safe_extract_zip(src, root)
        return root, tmp

    raise ValueError(f"Unsupported input. Expected folder or ZIP: {src}")


def iter_text_files(root: Path) -> Iterable[Path]:
    skip_dirs = {".git", "venv", "__pycache__", "loot", "exploits", "shells", "screenshots"}
    allowed_suffixes = {
        ".txt", ".md", ".html", ".htm", ".json", ".xml", ".yml", ".yaml",
        ".conf", ".config", ".log", ".csv", ".ini", ".out"
    }

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = set(path.relative_to(root).parts)
        if rel_parts & skip_dirs:
            continue
        if path.name.endswith((".pcap", ".cap", ".zip", ".7z", ".gz", ".tar", ".exe", ".dll", ".pdb")):
            continue
        if path.suffix.lower() in allowed_suffixes or "scans/" in str(path) or "enum/" in str(path):
            yield path


def parse_target_env(data: ReconData) -> None:
    text = data.files.get(".target.env", "")
    if not text:
        return
    m = BOX_LINE_RE.search(text)
    if m:
        data.box = m.group(1).strip()
    m = IP_LINE_RE.search(text)
    if m:
        data.ip = m.group(1).strip()
    m = HOST_LINE_RE.search(text)
    if m:
        data.host = m.group(1).strip()


def add_port(data: ReconData, num: int, service: str, version: str = "", proto: str = "tcp") -> None:
    if num not in data.ports:
        data.ports[num] = Port(num, service.strip(), version.strip(), proto)
    else:
        if service and not data.ports[num].service:
            data.ports[num].service = service.strip()
        if version and not data.ports[num].version:
            data.ports[num].version = version.strip()


def parse_ports(data: ReconData) -> None:
    candidates = [
        "scans/port-summary.md",
        "summary.md",
        "scans/tcp-services.txt",
        "scans/tcp-full.txt",
        "scans/udp-top100.txt",
    ]

    for rel in candidates:
        text = data.files.get(rel, "")
        if not text:
            continue

        for num, service, version in PORT_TABLE_RE.findall(text):
            if num.isdigit():
                add_port(data, int(num), service, version)

        for num, proto, service, version in NMAP_OPEN_RE.findall(text):
            if num.isdigit():
                add_port(data, int(num), service, version or "", proto)


def parse_web(data: ReconData) -> None:
    combined_web = []
    for rel, text in data.files.items():
        if rel.startswith("enum/web/") or rel in ("summary.md", "scans/tcp-services.txt", "scans/tcp-aggressive.txt"):
            combined_web.append((rel, text))

    for rel, text in combined_web:
        # Only collect URLs from high-signal files. Avoid web-candidates.txt and scanner help links.
        collect_urls = (
            rel.endswith("live-web-urls.txt")
            or "whatweb" in rel
            or rel == "summary.md"
            or rel.endswith(".html")
            or rel.endswith(".htm")
        )
        if collect_urls:
            for url in URL_RE.findall(text):
                low_url = url.lower()
                if any(x in low_url for x in (
                    "w3.org", "schema.org", "microsoft.com", "robtex.com", "github.com",
                    "developer.mozilla.org", "owasp.org", "netsparker.com", "nmap.org",
                    "nextjs.org", "react.dev"
                )):
                    continue
                # Avoid tiny placeholder URLs commonly embedded in minified JS/tests.
                if re.match(r"^https?://[a-z](?:[#/:?@]|$)", low_url):
                    continue
                data.web_urls.add(url.rstrip(".,);:"))

        if rel.startswith("enum/web/"):
            for endpoint in API_PATH_RE.findall(text):
                if is_interesting_path(endpoint):
                    data.endpoints.add(endpoint)

            for endpoint in FETCH_RE.findall(text):
                if endpoint.startswith("/"):
                    data.endpoints.add(endpoint)

            for action in FORM_ACTION_RE.findall(text):
                data.forms.add(html.unescape(action))

            for name in INPUT_RE.findall(text):
                data.inputs.add(html.unescape(name))

            for src in SCRIPT_SRC_RE.findall(text):
                data.js_files.add(html.unescape(src))

            for href in LINK_HREF_RE.findall(text):
                if href.startswith("/") and len(href) > 1:
                    data.endpoints.add(html.unescape(href))

        record_http_headers(data, text)
        detect_nextjs_from_text(data, text, rel)
        collect_nikto_noise(data, text)
        detect_tech_from_text(data, text)


def is_interesting_path(p: str) -> bool:
    if len(p) < 2 or len(p) > 200:
        return False
    low = p.lower()
    skip_prefix = ("/html", "/css", "/images", "/img", "/assets")
    if low.startswith(skip_prefix):
        return False
    keywords = [
        "/api", "/auth", "/login", "/admin", "/dashboard", "/user", "/setting",
        "/graphql", "/swagger", "/openapi", "/jwks", "/token", "/oauth",
        "/upload", "/download", "/backup", "/debug", "/dev", "/config"
    ]
    return any(k in low for k in keywords)


def version_tuple(version: str) -> tuple[int, int, int]:
    """
    Best-effort semver extraction. Non-numeric suffixes such as -rc are ignored.
    Missing parts default to zero.
    """
    nums = re.findall(r"\d+", version.split("-", 1)[0])
    parts = [int(x) for x in nums[:3]]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)  # type: ignore[return-value]


def version_lt(version: str, fixed: str) -> bool:
    return version_tuple(version) < version_tuple(fixed)


def looks_like_nextjs(data: ReconData) -> bool:
    tech = " ".join(sorted(data.technologies)).lower()
    return (
        "next.js" in tech
        or bool(data.nextjs_versions)
        or data.nextjs_app_router
        or any("/_next/static/" in js for js in data.js_files)
        or bool(data.rsc_indicators)
    )


def record_http_headers(data: ReconData, text: str) -> None:
    for name, value in HTTP_HEADER_RE.findall(text):
        lname = name.lower().strip()
        if lname in {
            "x-powered-by", "vary", "x-nextjs-cache", "x-nextjs-prerender",
            "server", "content-type", "location", "refresh",
            "content-security-policy", "x-frame-options",
        }:
            data.http_headers[lname].add(value.strip())


def detect_nextjs_from_text(data: ReconData, text: str, rel: str = "") -> None:
    low = text.lower()

    if "x-powered-by: next.js" in low or "/_next/static/" in low or "window.next" in low:
        data.technologies.add("Next.js")

    for m in NEXT_WINDOW_RE.finditer(text):
        version = m.group(1).strip()
        data.nextjs_versions.add(version)
        data.technologies.add(f"Next.js {version}")
        snippet = m.group(0)
        if re.search(r"appDir\s*:\s*!?0|appDir\s*:\s*true|appDir\s*:\s*!0", snippet):
            data.nextjs_app_router = True
            data.rsc_indicators.add("window.next appDir enabled")

    # Backup version extraction from minified bundles / text output.
    for m in re.finditer(r"""version\s*:\s*["'](1[0-6]\.[0-9][0-9A-Za-z.\-]*)["']""", text):
        # Restrict generic version: extraction to Next-ish bundles/HTML to avoid many false positives.
        if "next" in low or "/_next/" in rel.lower() or "appdir" in low:
            version = m.group(1).strip()
            data.nextjs_versions.add(version)
            data.technologies.add(f"Next.js {version}")

    for m in re.finditer(r"""appDir\s*:\s*(?:true|!0)""", text):
        data.nextjs_app_router = True
        data.rsc_indicators.add("appDir enabled")

    for m in re.finditer(r"""version\s*=\s*["'](1[789]\.[0-9][0-9A-Za-z.\-]*)["']""", text):
        version = m.group(1).strip()
        if "react" in low or "react.dev" in low:
            data.react_versions.add(version)
            data.technologies.add(f"React {version}")

    # Common React 19 RC strings in bundled apps.
    for m in re.finditer(r"""19\.0\.0-rc-[0-9A-Za-z-]+""", text):
        data.react_versions.add(m.group(0))
        data.technologies.add(f"React {m.group(0)}")

    if re.search(r"^vary:\s*.*\bRSC\b", text, re.IGNORECASE | re.MULTILINE):
        data.rsc_indicators.add("Vary header contains RSC")

    if re.search(r"^content-type:\s*text/x-component", text, re.IGNORECASE | re.MULTILINE):
        data.rsc_indicators.add("text/x-component response")

    if "next-router-state-tree" in low:
        data.rsc_indicators.add("Next-Router-State-Tree header/path observed")

    if "react server component" in low or "react-server-dom" in low:
        data.rsc_indicators.add("React Server Components string observed")

    for static_path in NEXT_STATIC_RE.findall(text):
        data.js_files.add(html.unescape(static_path))


def collect_nikto_noise(data: ReconData, text: str) -> None:
    if "nikto" not in text.lower() and "vulnerable to cross site scripting" not in text.lower():
        return
    cms_noise = ("post nuke", "postnuke", "drupal", "ez publish", "mywebserver")
    for line in text.splitlines():
        low = line.lower()
        if "vulnerable to cross site scripting" in low and any(x in low for x in cms_noise):
            if len(line) > 260:
                line = line[:260] + "..."
            data.nikto_likely_false_positives.append(line.strip())

def detect_tech_from_text(data: ReconData, text: str) -> None:
    patterns = [
        (r"pac4j-jwt/?([0-9.]+)?", "pac4j-jwt"),
        (r"\bpac4j\b", "pac4j"),
        (r"\bJetty\b", "Jetty"),
        (r"\bTomcat\b", "Tomcat"),
        (r"\bApache\b", "Apache HTTPD"),
        (r"\bnginx\b", "nginx"),
        (r"\bMicrosoft-HTTPAPI/2\.0\b", "Microsoft HTTPAPI"),
        (r"\bOpenSSH\s+([0-9][^\s]*)", "OpenSSH"),
        (r"\bMicrosoft SQL Server\s+([0-9][^;\n]*)", "Microsoft SQL Server"),
        (r"\bSQL Server 2022\b", "Microsoft SQL Server 2022"),
        (r"\.NET Message Framing", ".NET Message Framing"),
        (r"\bActive Directory LDAP\b", "Active Directory LDAP"),
        (r"\bMicrosoft Windows Kerberos\b", "Microsoft Kerberos"),
        (r"\bWindows Server 2022\b", "Windows Server 2022"),
        (r"X-Powered-By:\s*Next\.js|/_next/static/|\bNext\.js\b", "Next.js"),
        (r"\bJWT\b", "JWT"),
        (r"\bJWE\b", "JWE"),
        (r"\bJWKS\b", "JWKS"),
        (r"\bBearer\b", "Bearer Token"),
        (r"\bWinRM\b|\bwsman\b", "WinRM"),
        (r"\bRDP\b|ms-wbt-server", "RDP"),
    ]
    for pat, name in patterns:
        if re.search(pat, text, re.IGNORECASE):
            # Preserve exact version for some patterns where possible.
            if name == "pac4j-jwt":
                m = re.search(r"pac4j-jwt/?([0-9.]+)?", text, re.IGNORECASE)
                if m and m.group(1):
                    data.technologies.add(f"pac4j-jwt/{m.group(1).rstrip('.,')}")
                else:
                    data.technologies.add(name)
            elif name == "OpenSSH":
                m = re.search(r"\bOpenSSH\s+([0-9][^\s]*)", text, re.IGNORECASE)
                data.technologies.add(f"OpenSSH {m.group(1)}" if m else name)
            elif name == "Microsoft SQL Server":
                m = re.search(r"\bMicrosoft SQL Server\s+([0-9][^;\n]*)", text, re.IGNORECASE)
                data.technologies.add(f"Microsoft SQL Server {m.group(1).strip()}" if m else name)
            else:
                data.technologies.add(name)


def normalize_web_ports(data: ReconData) -> None:
    """
    Nmap sometimes labels custom HTTP ports as unknown/ppp?. If the recon files
    clearly show HTTP/Next.js on that port, relabel the service for the report.
    """
    for port in list(data.ports.values()):
        port_s = str(port.number)
        if any(f":{port_s}" in u for u in data.web_urls) or (
            port.number == 3000 and looks_like_nextjs(data)
        ):
            if not port.service or port.service.lower() in {"ppp?", "unknown"}:
                port.service = "http"
            if looks_like_nextjs(data) and "next.js" not in port.version.lower():
                version = ", ".join(sorted(data.nextjs_versions))
                port.version = f"Next.js {version}".strip()

def parse_smb(data: ReconData) -> None:
    for rel, text in data.files.items():
        if not rel.startswith("enum/smb/") and rel not in ("summary.md",):
            continue

        # smbclient share table lines.
        for line in text.splitlines():
            line_clean = line.strip()
            m = re.match(r"^([A-Za-z0-9_.-]+\$?)\s+(Disk|IPC)\s*(.*)$", line_clean)
            if m and m.group(1) not in {"Sharename"}:
                data.smb_shares.add(m.group(1))

        # netexec hints.
        m = re.search(r"\(name:([^)]+?)\)\s+\(domain:([^)]+?)\)", text, re.IGNORECASE)
        if m:
            data.computer = data.computer or m.group(1).strip()
            data.domain = data.domain or m.group(2).strip()

        m = re.search(r"Domain Name:\s*([A-Za-z0-9_.-]+)", text)
        if m:
            data.domain = data.domain or m.group(1).lower()


def parse_ad_dns_ldap(data: ReconData) -> None:
    for rel, text in data.files.items():
        if rel.startswith(("enum/ldap/", "enum/dns/")) or rel in ("summary.md", "scans/tcp-services.txt", "scans/tcp-aggressive.txt"):
            for nc in re.findall(r"namingcontexts?:\s*([^\n\r]+)", text, re.IGNORECASE):
                data.naming_contexts.add(nc.strip())

            m = re.search(r"DNS_Domain_Name:\s*([A-Za-z0-9_.-]+)", text)
            if m:
                data.domain = data.domain or m.group(1).strip()

            m = re.search(r"DNS_Computer_Name:\s*([A-Za-z0-9_.-]+)", text)
            if m:
                data.computer = data.computer or m.group(1).strip()

            m = re.search(r"Domain:\s*([A-Za-z0-9_.-]+)", text)
            if m:
                data.domain = data.domain or m.group(1).strip()

            m = re.search(r"ldapServiceName:\s*([^:\s]+):([^@\s]+)@", text, re.IGNORECASE)
            if m:
                data.domain = data.domain or m.group(1).strip()
                data.computer = data.computer or m.group(2).replace("$", "").strip()


def parse_interesting(data: ReconData) -> None:
    text = data.files.get("enum/interesting-grep.txt", "")
    if not text:
        return
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if not line or "enum/interesting-grep.txt:enum/interesting-grep.txt" in line:
            continue
        if len(line) > 300:
            line = line[:300] + "..."
        lines.append(line)
    data.interesting_lines = lines[:80]


def load_recon(root: Path, source: Path) -> ReconData:
    data = ReconData(root=root, source=source)

    for path in iter_text_files(root):
        rel = path.relative_to(root).as_posix()
        data.files[rel] = read_text(path)

    parse_target_env(data)
    parse_ports(data)
    parse_web(data)
    normalize_web_ports(data)
    parse_smb(data)
    parse_ad_dns_ldap(data)
    parse_interesting(data)

    # Fallback target from summary if .target.env missing.
    summary = data.files.get("summary.md", "")
    if not data.ip:
        m = re.search(r"^- IP:\s*(.+)$", summary, re.MULTILINE)
        if m:
            data.ip = m.group(1).strip()
    if not data.host:
        m = re.search(r"^- Hostname:\s*(.+)$", summary, re.MULTILINE)
        if m:
            data.host = m.group(1).strip()
    if not data.box:
        m = re.search(r"^# Recon Summary -\s*(.+)$", summary, re.MULTILINE)
        if m:
            data.box = m.group(1).strip()

    return data


def detect_profile(data: ReconData) -> list[str]:
    profiles = []
    ports = set(data.ports)
    tech = " ".join(sorted(data.technologies)).lower()

    if {88, 389, 445}.issubset(ports) or "active directory" in tech:
        profiles.append("Windows Active Directory / Domain Controller")
    elif any("windows" in t.lower() for t in data.technologies) or 445 in ports:
        profiles.append("Windows")
    else:
        profiles.append("Linux/Unix or unknown")

    if any(p in ports for p in (80, 443, 3000, 5000, 8000, 8080, 8443, 9000, 9090, 10000)) or data.web_urls:
        profiles.append("Web application")
    if 445 in ports:
        profiles.append("SMB exposed")
    if 389 in ports or 3268 in ports:
        profiles.append("LDAP exposed")
    if 88 in ports:
        profiles.append("Kerberos exposed")
    if 5985 in ports or 5986 in ports:
        profiles.append("WinRM exposed")
    if 1433 in ports or 6520 in ports or "sql server" in tech:
        profiles.append("MSSQL exposed")
    if 9389 in ports or ".net message framing" in tech:
        profiles.append(".NET/ADWS-style service exposed")

    return profiles


def build_findings(data: ReconData) -> list[Finding]:
    findings: list[Finding] = []
    ports = set(data.ports)
    tech = " ".join(sorted(data.technologies)).lower()
    endpoints_low = {e.lower() for e in data.endpoints}
    shares_low = {s.lower() for s in data.smb_shares}

    # Diagnostic fallback: no ports means recon/connectivity failed or target is unusual.
    if not data.ports:
        findings.append(Finding(
            "No open ports parsed from recon output",
            "The analyzer did not parse any confirmed open ports. Before chasing exploits, verify target IP, VPN route, machine state, and whether the TCP discovery scan actually completed.",
            "high",
            evidence=[
                "No entries matched '<port>/tcp open' or the port summary table.",
                f"Target: {data.ip or data.host or 'unknown'}",
            ],
            commands=[
                f"ip route get {data.ip or '<target-ip>'}",
                f"ping -c 3 {data.ip or '<target-ip>'}",
                f"sudo nmap -p- -sS -Pn --reason --max-retries 3 --min-rate 1000 {data.ip or '<target-ip>'} -oN scans/tcp-full-retry.txt",
                f"sudo nmap -Pn --reason -p 21,22,25,53,80,88,111,135,139,389,443,445,464,593,636,3000,5000,8080,8443,5985,5986 {data.ip or '<target-ip>'} -oN scans/tcp-common-retry.txt",
            ],
        ))

    # Next.js / React Server Components fingerprinting.
    if looks_like_nextjs(data):
        evidence = []
        if data.nextjs_versions:
            evidence.append("Next.js version(s): " + ", ".join(sorted(data.nextjs_versions)))
        if data.react_versions:
            evidence.append("React version(s): " + ", ".join(sorted(data.react_versions)))
        if data.nextjs_app_router:
            evidence.append("App Router/appDir enabled")
        if data.rsc_indicators:
            evidence.append("RSC indicators: " + ", ".join(sorted(data.rsc_indicators)))
        if data.js_files:
            evidence.append("Next static JS chunks: " + ", ".join(sorted([j for j in data.js_files if "/_next/static/" in j])[:5]))

        commands = [
            "grep -Rho 'window.next={[^}]*}' enum/web/js-* enum/web/*.html 2>/dev/null | sort -u",
            "grep -RhoE '19\\.0\\.0-rc-[0-9A-Za-z-]+' enum/web/js-* enum/web/*.html 2>/dev/null | sort -u",
            f"curl -i http://{data.host or data.ip}:3000/ -H 'RSC: 1'",
            f"curl -i 'http://{data.host or data.ip}:3000/?_rsc=test'",
            "grep -RniE 'server action|server function|use server|react-server-dom|Next-Router-State-Tree|x-action|_rsc|appDir' enum/web/",
        ]

        high_risk = False
        for v in data.nextjs_versions:
            # Next.js 15.0.3-like versions are below the known fixed versions for both the
            # RSC advisory line and middleware authorization bypass checks.
            if version_tuple(v) >= (15, 0, 0) and version_lt(v, "15.0.5") and (data.nextjs_app_router or data.rsc_indicators):
                high_risk = True

        detail = (
            "Next.js/App Router/RSC artifacts were detected. This is high-value because modern Next.js attack paths may be framework-level and may not require visible forms or obvious inputs."
            if high_risk else
            "Next.js artifacts were detected. Review framework version, App Router/RSC behavior, middleware, routes, and server actions before generic brute forcing."
        )

        findings.append(Finding(
            "Next.js / React Server Components attack surface",
            detail,
            "high" if high_risk else "medium",
            evidence=evidence or ["Next.js-like artifacts detected"],
            commands=commands,
        ))

        # Middleware bypass check is only useful when protected routes exist, but version-wise it deserves a note.
        if any(version_tuple(v) >= (15, 0, 0) and version_lt(v, "15.2.3") for v in data.nextjs_versions):
            findings.append(Finding(
                "Next.js middleware authorization-bypass candidate",
                "The detected Next.js version is in a range where middleware-based authorization bypass should be manually tested if protected routes such as /admin or /dashboard exist.",
                "medium",
                evidence=["Next.js version(s): " + ", ".join(sorted(data.nextjs_versions))],
                commands=[
                    f"for p in admin dashboard login internal monitor monitoring api/status api/health; do echo ===== /$p =====; curl -s -i http://{data.host or data.ip}:3000/$p | head -n 20; done",
                    f"curl -i http://{data.host or data.ip}:3000/admin -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware'",
                ],
            ))

    if data.nikto_likely_false_positives and looks_like_nextjs(data):
        findings.append(Finding(
            "Likely Nikto CMS/XSS false positives",
            "Nikto reported old CMS XSS signatures, but the app fingerprints as Next.js. Treat these as low-confidence noise unless you can prove reflection in this app.",
            "low",
            evidence=data.nikto_likely_false_positives[:6],
            commands=[
                "grep -RniE 'vulnerable to Cross Site Scripting|Post Nuke|Drupal|eZ publish|MyWebServer' enum/web/nikto-*",
                "Manually verify reflection before documenting XSS as a finding.",
            ],
        ))

    # AD/DC fingerprint.
    if {53, 88, 389, 445}.issubset(ports) or "active directory" in tech:
        findings.append(Finding(
            "Windows AD/DC-style attack surface",
            "DNS, Kerberos, LDAP and SMB are exposed. Treat this as an Active Directory target and prioritize domain enumeration.",
            "high",
            evidence=[
                f"Ports: {', '.join(str(p) for p in sorted(ports & {53, 88, 389, 445, 464, 636, 3268, 3269}))}",
                f"Domain: {data.domain or data.host}",
                f"Computer: {data.computer or 'unknown'}",
            ],
            commands=[
                f"netexec smb {data.ip} -u guest -p '' --shares",
                f"ldapsearch -x -H ldap://{data.ip} -s base namingcontexts",
                f"nxc ldap {data.ip} -u guest -p '' --users",
            ],
        ))

    # Null/guest SMB and interesting shares.
    if 445 in ports and data.smb_shares:
        shares = sorted(data.smb_shares)
        detail = "SMB shares were enumerated. Review non-default shares first."
        confidence = "high" if any(s.lower() not in {"admin$", "c$", "ipc$", "netlogon", "sysvol"} for s in shares) else "medium"
        commands = [
            f"smbclient -L //{data.ip} -U '%'",
        ]
        for share in shares:
            if share.lower() not in {"admin$", "c$", "ipc$", "netlogon", "sysvol"}:
                commands.append(f"smbclient //{data.ip}/{share} -U '%'")
        findings.append(Finding(
            "SMB share enumeration produced accessible share names",
            detail,
            confidence,
            evidence=[", ".join(shares)],
            commands=commands,
        ))

    if "software$" in shares_low:
        findings.append(Finding(
            "High-value SMB share: software$",
            "A non-default software$ share exists. Download and inspect binaries, configs, scripts, and connection strings.",
            "high",
            evidence=["Share: software$"],
            commands=[
                f"mkdir -p loot/software && cd loot/software",
                f"smbclient //{data.ip}/software$ -U '%' -c 'recurse ON; prompt OFF; mget *'",
                "find . -type f",
                "grep -RniE \"password|user|uid|pwd|server|sql|connection|string\" .",
            ],
        ))

    # MSSQL.
    if 1433 in ports or 6520 in ports or "sql server" in tech:
        port = 6520 if 6520 in ports else 1433
        findings.append(Finding(
            "MSSQL service exposed",
            "MSSQL is exposed. Look for credentials in SMB shares, configs, source files, or notes, then test SQL authentication and linked servers.",
            "high",
            evidence=[f"Port {port}", *[t for t in sorted(data.technologies) if "SQL Server" in t]],
            commands=[
                f"netexec mssql {data.ip} --port {port} -u <user> -p '<password>'",
                f"impacket-mssqlclient '<domain>/<user>:<password>@{data.host or data.ip}' -p {port} -windows-auth",
                "select @@version;",
                "select suser_name();",
                "select name from sys.servers;",
            ],
        ))

    # WinRM.
    if 5985 in ports or 5986 in ports:
        findings.append(Finding(
            "WinRM exposed",
            "WinRM is available. Any recovered domain credentials should be tested for remote shell access.",
            "high",
            evidence=[f"Port {'5985' if 5985 in ports else '5986'}"],
            commands=[
                f"netexec winrm {data.ip} -u <user> -p '<password>'",
                f"evil-winrm -i {data.host or data.ip} -u <user> -p '<password>'",
            ],
        ))

    # .NET / WCF-ish.
    if 9389 in ports or ".net message framing" in tech:
        findings.append(Finding(
            ".NET Message Framing / ADWS-style service present",
            "Port 9389 or .NET Message Framing was detected. On Windows targets, later local enumeration should check for WCF/.NET services and localhost-only endpoints.",
            "medium",
            evidence=["9389/tcp" if 9389 in ports else ".NET Message Framing technology indicator"],
            commands=[
                "Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services'",
                "netstat -ano | findstr LISTENING",
                "iwr 'http://localhost:8000/MonitorService?wsdl' -UseBasicParsing",
            ],
        ))

    # Web/JWT/JWE/JWKS.
    if "pac4j-jwt" in tech or any("jwks" in e for e in endpoints_low) or "jwe" in tech or "jwt" in tech:
        findings.append(Finding(
            "JWT/JWE/JWKS authentication indicators",
            "JWT/JWE terms or JWKS endpoints were found. Review token handling, exposed keys, role claims, and alg/verification behavior manually.",
            "high" if "pac4j-jwt" in tech else "medium",
            evidence=[
                *[t for t in sorted(data.technologies) if any(k in t.lower() for k in ("jwt", "jwe", "jwks", "pac4j"))],
                *sorted([e for e in data.endpoints if any(k in e.lower() for k in ("jwks", "token", "auth", "login"))])[:10],
            ],
            commands=[
                f"curl -s http://{data.ip}:<port>/api/auth/jwks | jq",
                "grep -RniE \"jwt|jwe|jwks|token|bearer|role|sessionStorage|localStorage\" enum/web/",
                "Search terms: pac4j-jwt <version> JWE JWT auth bypass",
            ],
        ))

    # Web app general.
    if data.web_urls or data.endpoints or any(p in ports for p in (80, 443, 3000, 5000, 8000, 8080, 8443, 9000, 9090, 10000)):
        commands = [
            "cat enum/web/live-web-urls.txt",
            "grep -RniE \"fetch|axios|/api/|token|auth|login|admin|dashboard|password|secret\" enum/web/",
        ]
        findings.append(Finding(
            "Web application artifacts found",
            "Review collected HTML, headers, JavaScript, forms, and API endpoints. This is often more useful than adding more brute force.",
            "medium",
            evidence=[
                f"URLs: {', '.join(sorted(data.web_urls)[:8]) or 'none listed'}",
                f"Endpoints: {', '.join(sorted(data.endpoints)[:12]) or 'none extracted'}",
                f"Forms: {', '.join(sorted(data.forms)[:6]) or 'none extracted'}",
            ],
            commands=commands,
        ))

    # SSH.
    if 22 in ports:
        findings.append(Finding(
            "SSH exposed",
            "SSH is exposed. Prioritize credential reuse only after finding users/passwords from other services.",
            "low",
            evidence=[f"Version: {data.ports[22].version or data.ports[22].service}"],
            commands=[
                f"netexec ssh {data.ip} -u users.txt -p '<password>'",
                f"ssh <user>@{data.ip}",
            ],
        ))

    # DNS.
    if 53 in ports:
        findings.append(Finding(
            "DNS service exposed",
            "DNS is exposed. Zone transfer and record enumeration should be reviewed. On AD, DNS records may become useful after credentials are obtained.",
            "medium",
            evidence=[f"Host/domain: {data.host or data.domain or 'unknown'}"],
            commands=[
                f"dig @{data.ip} {data.host or '<domain>'} ANY",
                f"dig axfr @{data.ip} {data.host or '<domain>'}",
                f"dnsrecon -d {data.host or '<domain>'} -n {data.ip} -a",
            ],
        ))

    return findings


def cve_search_suggestions(data: ReconData) -> list[str]:
    suggestions = []
    techs = sorted(data.technologies)
    # High-signal framework suggestions.
    if looks_like_nextjs(data):
        if data.nextjs_versions:
            versions = ", ".join(sorted(data.nextjs_versions))
            suggestions.append(f"Next.js {versions} App Router RSC CVE-2025-66478 React Server Components RCE fixed 15.0.5")
            suggestions.append(f"Next.js {versions} CVE-2025-29927 x-middleware-subrequest authorization bypass fixed 15.2.3")
        else:
            suggestions.append("Next.js App Router React Server Components RSC vulnerability check")
    for t in techs:
        low = t.lower()
        if "pac4j-jwt" in low:
            suggestions.append(f"{t} JWE JWT authentication bypass CVE")
        elif "jetty" in low:
            suggestions.append(f"{t} vulnerabilities HTB")
        elif "microsoft sql server" in low:
            suggestions.append(f"{t} linked server xp_dirtree coercion credentials")
        elif "openssh" in low:
            suggestions.append(f"{t} privilege escalation CVE check version distro backports")
        elif ".net message framing" in low:
            suggestions.append(".NET Message Framing WCF localhost service command injection")
        elif "active directory" in low:
            suggestions.append("Active Directory null session SMB LDAP DNS abuse HTB")
        elif "winrm" in low:
            suggestions.append("WinRM valid credentials remote shell evil-winrm")
    # De-dupe while preserving order.
    out = []
    seen = set()
    for s in suggestions:
        if s not in seen:
            out.append(s)
            seen.add(s)
    return out[:12]


def md_escape(s: str) -> str:
    return s.replace("|", "\\|").strip()


def render_report(data: ReconData, findings: list[Finding]) -> str:
    lines: list[str] = []
    lines.append(f"# Recon Analysis - {data.box or data.source.stem}")
    lines.append("")
    lines.append("## Target")
    lines.append("")
    lines.append(f"- Source: `{data.source}`")
    lines.append(f"- Workspace: `{data.root}`")
    lines.append(f"- Box: `{data.box or 'unknown'}`")
    lines.append(f"- IP: `{data.ip or 'unknown'}`")
    lines.append(f"- Hostname: `{data.host or 'unknown'}`")
    if data.domain:
        lines.append(f"- Domain: `{data.domain}`")
    if data.computer:
        lines.append(f"- Computer: `{data.computer}`")
    lines.append("")

    lines.append("## Detected Profile")
    lines.append("")
    for profile in detect_profile(data):
        lines.append(f"- {profile}")
    lines.append("")

    lines.append("## Open Ports")
    lines.append("")
    if data.ports:
        lines.append("| Port | Proto | Service | Version |")
        lines.append("|---:|---|---|---|")
        for p in sorted(data.ports.values(), key=lambda x: (x.proto, x.number)):
            lines.append(f"| {p.number} | {md_escape(p.proto)} | {md_escape(p.service)} | {md_escape(p.version)} |")
    else:
        lines.append("_No ports parsed._")
    lines.append("")

    lines.append("## Detected Technologies")
    lines.append("")
    if data.technologies:
        for t in sorted(data.technologies, key=str.lower):
            lines.append(f"- {t}")
    else:
        lines.append("_No technology indicators parsed._")
    lines.append("")


    if looks_like_nextjs(data):
        lines.append("## Next.js / React Intelligence")
        lines.append("")
        if data.nextjs_versions:
            lines.append("- Next.js version(s): `" + "`, `".join(sorted(data.nextjs_versions)) + "`")
        if data.react_versions:
            lines.append("- React version(s): `" + "`, `".join(sorted(data.react_versions)) + "`")
        lines.append(f"- App Router / appDir detected: `{'yes' if data.nextjs_app_router else 'unknown/no'}`")
        if data.rsc_indicators:
            lines.append("- RSC indicators:")
            for i in sorted(data.rsc_indicators):
                lines.append(f"  - `{i}`")
        if data.http_headers:
            lines.append("- High-signal HTTP headers:")
            for h in sorted(data.http_headers):
                vals = "; ".join(sorted(data.http_headers[h]))[:220]
                lines.append(f"  - `{h}: {vals}`")
        lines.append("")

    if data.web_urls or data.endpoints or data.js_files or data.forms or data.inputs:
        lines.append("## Web Intelligence")
        lines.append("")
        if data.web_urls:
            lines.append("### URLs")
            for u in sorted(data.web_urls)[:30]:
                lines.append(f"- `{u}`")
            lines.append("")
        if data.js_files:
            lines.append("### JavaScript Files")
            for js in sorted(data.js_files)[:30]:
                lines.append(f"- `{js}`")
            lines.append("")
        if data.endpoints:
            lines.append("### Extracted Endpoints / Paths")
            for e in sorted(data.endpoints)[:80]:
                lines.append(f"- `{e}`")
            lines.append("")
        if data.forms or data.inputs:
            lines.append("### Forms / Inputs")
            if data.forms:
                lines.append("Forms:")
                for f in sorted(data.forms)[:20]:
                    lines.append(f"- `{f}`")
            if data.inputs:
                lines.append("Inputs:")
                for i in sorted(data.inputs)[:30]:
                    lines.append(f"- `{i}`")
            lines.append("")

    if data.smb_shares or data.naming_contexts:
        lines.append("## AD / SMB / LDAP Intelligence")
        lines.append("")
        if data.smb_shares:
            lines.append("### SMB Shares")
            for s in sorted(data.smb_shares, key=str.lower):
                marker = " ⭐" if s.lower() not in {"admin$", "c$", "ipc$", "netlogon", "sysvol"} else ""
                lines.append(f"- `{s}`{marker}")
            lines.append("")
        if data.naming_contexts:
            lines.append("### LDAP Naming Contexts")
            for nc in sorted(data.naming_contexts):
                lines.append(f"- `{nc}`")
            lines.append("")

    lines.append("## Prioritized Findings and Next Steps")
    lines.append("")
    if not findings:
        lines.append("_No prioritized findings generated._")
    for idx, f in enumerate(findings, 1):
        lines.append(f"### {idx}. {f.title}")
        lines.append("")
        lines.append(f"- Confidence: **{f.confidence.upper()}**")
        lines.append(f"- Detail: {f.detail}")
        if f.evidence:
            lines.append("- Evidence:")
            for e in f.evidence:
                if e:
                    lines.append(f"  - `{e}`")
        if f.commands:
            lines.append("- Manual verification commands:")
            lines.append("")
            lines.append("```bash")
            for c in f.commands:
                lines.append(c)
            lines.append("```")
        lines.append("")

    suggestions = cve_search_suggestions(data)
    lines.append("## CVE / Research Search Suggestions")
    lines.append("")
    if suggestions:
        for s in suggestions:
            lines.append(f"- `{s}`")
    else:
        lines.append("_No specific CVE/search suggestions generated._")
    lines.append("")

    if data.interesting_lines:
        lines.append("## Interesting Grep Highlights")
        lines.append("")
        for line in data.interesting_lines[:50]:
            lines.append(f"- `{line}`")
        lines.append("")

    lines.append("## Files Parsed")
    lines.append("")
    for rel in sorted(data.files)[:300]:
        lines.append(f"- `{rel}`")
    if len(data.files) > 300:
        lines.append(f"- ... truncated, {len(data.files) - 300} additional files")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("Generated by `analyze-recon.py`. Treat all exploit suggestions as hypotheses requiring manual validation.")
    lines.append("")

    return "\n".join(lines)


def default_output_path(input_path: Path, root: Path, is_zip: bool) -> Path:
    if is_zip:
        return input_path.with_name(input_path.stem + "-analysis.md")
    return root / "recon-analysis.md"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze htb-init recon folder or ZIP and generate recon-analysis.md"
    )
    parser.add_argument("input", help="Path to htb-init workspace folder or recon ZIP")
    parser.add_argument("-o", "--output", help="Output Markdown path")
    parser.add_argument("--print", action="store_true", help="Print report to stdout as well")
    args = parser.parse_args()

    src = Path(args.input)
    is_zip = src.is_file() and zipfile.is_zipfile(src)

    tmp_obj = None
    try:
        root, tmp_obj = materialize_input(src)
        data = load_recon(root, src)
        findings = build_findings(data)
        report = render_report(data, findings)

        out_path = Path(args.output).expanduser().resolve() if args.output else default_output_path(src.expanduser().resolve(), root, is_zip)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report, encoding="utf-8")

        print(f"[+] Parsed files: {len(data.files)}")
        print(f"[+] Open ports parsed: {len(data.ports)}")
        print(f"[+] Findings generated: {len(findings)}")
        print(f"[+] Wrote analysis: {out_path}")

        if args.print:
            print()
            print(report)

        return 0
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        return 1
    finally:
        if tmp_obj is not None:
            tmp_obj.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
