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
- Make no network requests.

Usage:
  python3 analyze-recon.py /home/zendeni/htb_labs/principal
  python3 analyze-recon.py /home/zendeni/htb_labs/principal/principal-recon-*.zip
  python3 analyze-recon.py <target> -o /tmp/recon-analysis.md --print

Design notes:
- This script is a hint engine, not an exploit oracle.
- Findings are suggestions for manual verification.
- All exploit/CVE notes are hypotheses until manually validated.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional


MAX_READ_BYTES = 2_000_000
MAX_ZIP_FILES = 10_000
MAX_ZIP_UNCOMPRESSED_BYTES = 750_000_000
DEFAULT_VULN_CACHE = Path.home() / ".cache" / "htb-recon" / "vuln-cache.json"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
API_PATH_RE = re.compile(r"""(?:"|')((?:/[A-Za-z0-9._~!$&'()*+,;=:@%-]+){1,})(?:"|')""")
FETCH_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|XMLHttpRequest|open)\s*\(?\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
FORM_ACTION_RE = re.compile(r"""<form[^>]+action=["']?([^"'\s>]+)""", re.IGNORECASE)
INPUT_RE = re.compile(r"""<input[^>]+(?:name|id)=["']?([^"'\s>]+)""", re.IGNORECASE)
SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)
LINK_HREF_RE = re.compile(r"""<a[^>]+href=["']([^"']+)["']""", re.IGNORECASE)
PORT_TABLE_RE = re.compile(r"^\|\s*(\d+)\s*\|\s*([^\n|]+?)\s*\|\s*([^\n|]*?)\s*\|", re.MULTILINE)
NMAP_OPEN_RE = re.compile(
    r"^(\d+)/(tcp|udp)[^\S\r\n]+open[^\S\r\n]+(\S+)(?:[^\S\r\n]+([^\r\n]*))?$",
    re.MULTILINE,
)
HOST_LINE_RE = re.compile(r"^\s*HOST=\"?([^\"\n]+)\"?\s*$", re.MULTILINE)
IP_LINE_RE = re.compile(r"^\s*IP=\"?([^\"\n]+)\"?\s*$", re.MULTILINE)
BOX_LINE_RE = re.compile(r"^\s*BOX=\"?([^\"\n]+)\"?\s*$", re.MULTILINE)

NEXT_WINDOW_RE = re.compile(
    r"""window\.next\s*=\s*\{[^}]*?version\s*:\s*["']([^"']+)["'][^}]*?\}""",
    re.IGNORECASE | re.DOTALL,
)
NEXT_VERSION_RE = re.compile(
    r"""(?:Next\.js|next)["'\s:=/_-]{0,20}(?:version)?["'\s:=/_-]{0,20}(1[0-6]\.[0-9]+(?:\.[0-9]+)?[0-9A-Za-z.\-+]*)""",
    re.IGNORECASE,
)
REACT_VERSION_RE = re.compile(
    r"""(?:React|react)["'\s:=/_-]{0,20}(?:version)?["'\s:=/_-]{0,20}(1[789]\.[0-9]+(?:\.[0-9]+)?[0-9A-Za-z.\-+]*)""",
    re.IGNORECASE,
)
NEXT_STATIC_RE = re.compile(r"""(?:src|href)=["']([^"']*/_next/static/[^"']+)["']""", re.IGNORECASE)
HTTP_HEADER_RE = re.compile(r"""^([A-Za-z0-9-]+):\s*(.+)$""", re.MULTILINE)


# Default-port and weak-signal technology inference.
# These rules intentionally create hypotheses, not proof. They are useful when
# Nmap reports tcpwrapped/unknown but the port itself is high-signal.
PORT_TECH_RULES: dict[int, dict[str, object]] = {
    10050: {
        "tech": "Zabbix",
        "service": "zabbix-agent",
        "confidence": "medium",
        "detail": "10050/tcp is the default Zabbix agent port.",
        "version_commands": [
            "zabbix_get -s {target} -p 10050 -k agent.version",
            "zabbix_get -s {target} -p 10050 -k system.hostname",
            "zabbix_get -s {target} -p 10050 -k system.uname",
        ],
    },
    10051: {
        "tech": "Zabbix",
        "service": "zabbix-server",
        "confidence": "medium",
        "detail": "10051/tcp is the default Zabbix server/trapper port.",
        "version_commands": [
            "nmap -sT -sV -sC -p10050,10051 --version-all {target}",
            "for p in zabbix api_jsonrpc.php zabbix/api_jsonrpc.php zabbix/index.php; do echo ===== /$p =====; curl -s -i 'http://{target}/'$p | head -n 30; done",
        ],
    },
    8111: {
        "tech": "TeamCity",
        "service": "teamcity",
        "confidence": "medium",
        "detail": "8111/tcp is commonly used by JetBrains TeamCity.",
        "version_commands": [
            "curl -s -i 'http://{target}:8111/' | head -n 40",
            "curl -s 'http://{target}:8111/login.html' | grep -iE 'teamcity|version'",
        ],
    },
    8080: {
        "tech": "Java web service",
        "service": "http-alt",
        "confidence": "low",
        "detail": "8080/tcp is a common alternate HTTP port used by Tomcat, Jenkins, TeamCity, Spring Boot, and other Java web services.",
        "version_commands": [
            "curl -s -i 'http://{target}:8080/' | head -n 40",
            "whatweb -a 3 'http://{target}:8080/'",
        ],
    },
    3000: {
        "tech": "Node.js web service",
        "service": "http-node",
        "confidence": "low",
        "detail": "3000/tcp is commonly used by Node.js/Next.js/Express/Grafana development services.",
        "version_commands": [
            "curl -s -i 'http://{target}:3000/' | head -n 40",
            "whatweb -a 3 'http://{target}:3000/'",
        ],
    },
    5000: {
        "tech": "Python/Flask or Docker Registry candidate",
        "service": "http-alt",
        "confidence": "low",
        "detail": "5000/tcp is commonly used by Flask/Werkzeug apps and Docker Registry.",
        "version_commands": [
            "curl -s -i 'http://{target}:5000/' | head -n 40",
            "curl -s -i 'http://{target}:5000/v2/' | head -n 40",
        ],
    },
    6379: {
        "tech": "Redis",
        "service": "redis",
        "confidence": "medium",
        "detail": "6379/tcp is the default Redis port.",
        "version_commands": [
            "redis-cli -h {target} -p 6379 INFO server",
        ],
    },
    9200: {
        "tech": "Elasticsearch",
        "service": "elasticsearch",
        "confidence": "medium",
        "detail": "9200/tcp is the default Elasticsearch HTTP API port.",
        "version_commands": [
            "curl -s 'http://{target}:9200/' | jq .",
        ],
    },
    27017: {
        "tech": "MongoDB",
        "service": "mongodb",
        "confidence": "medium",
        "detail": "27017/tcp is the default MongoDB port.",
        "version_commands": [
            "mongosh --host {target} --eval 'db.version()'",
        ],
    },
}

# Local hypothesis rules for well-known CVEs that are easy to miss when only a
# port or weak fingerprint is present. These are not vulnerability claims; they
# create research candidates with explicit manual validation steps.
OFFLINE_CVE_RULES: list[dict[str, object]] = [
    {
        "id": "CVE-2024-22120",
        "product": "Zabbix",
        "severity": "HIGH/CRITICAL candidate",
        "confidence": "medium",
        "impact_keywords": ["remote code execution", "rce", "sql injection", "command execution"],
        "version_ranges": ["6.0.0-6.0.27", "6.4.0-6.4.12", "7.0.0alpha1-7.0.0beta1"],
        "hints": ["zabbix", "10050", "10051", "api_jsonrpc.php", "/zabbix"],
        "title": "Zabbix Server audit log clientip SQL injection / RCE-chain research candidate",
        "summary": "Possible Zabbix exposure was detected. Research CVE-2024-22120 after confirming Zabbix Server/frontend/API access and version. Do not treat this as confirmed vulnerable without version and access validation.",
        "references": [
            "https://support.zabbix.com/browse/ZBX-24505",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-22120",
        ],
        "verification": [
            "Locate the Zabbix frontend or API endpoint, commonly /zabbix/ or /api_jsonrpc.php.",
            "Identify the Zabbix Server version from the UI, API, package files, or agent/server banners.",
            "Check whether the confirmed version falls in 6.0.0-6.0.27, 6.4.0-6.4.12, or 7.0.0 alpha/beta affected ranges.",
            "Validate exploit prerequisites before attempting any exploit path.",
        ],
    },
]

ZABBIX_VERSION_RE = re.compile(
    r"""\bZabbix(?:\s+(?:Server|Agent|Frontend))?[/'\s:-]*(\d+\.\d+(?:\.\d+)?(?:alpha\d+|beta\d+|rc\d+)?[0-9A-Za-z.\-+]*)""",
    re.IGNORECASE,
)


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
class VulnMatch:
    source: str
    vuln_id: str
    title: str = ""
    severity: str = "unknown"
    package: str = ""
    ecosystem: str = ""
    version: str = ""
    confidence: str = "medium"
    summary: str = ""
    references: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    relevance: int = 0
    reason: str = ""


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
    package_versions: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    vuln_matches: list[VulnMatch] = field(default_factory=list)
    vuln_errors: list[str] = field(default_factory=list)


def strip_ansi(s: str) -> str:
    return CONTROL_RE.sub("", ANSI_RE.sub("", s))


def read_text(path: Path, max_bytes: int = MAX_READ_BYTES) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""

    if b"\x00" in data[:4096]:
        return ""

    if len(data) > max_bytes:
        data = data[:max_bytes]

    return strip_ansi(data.decode("utf-8", errors="ignore"))


def is_safe_zip_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    if not normalized or normalized.startswith("/"):
        return False
    if re.match(r"^[A-Za-z]:/", normalized):
        return False
    parts = Path(normalized).parts
    return all(part not in {"", ".", ".."} for part in parts)


def safe_extract_zip(zip_path: Path, dest: Path) -> None:
    dest_resolved = dest.resolve()
    total_uncompressed = 0

    with zipfile.ZipFile(zip_path) as zf:
        members = zf.infolist()
        if len(members) > MAX_ZIP_FILES:
            raise RuntimeError(f"ZIP has too many entries: {len(members)} > {MAX_ZIP_FILES}")

        for member in members:
            name = member.filename
            if not name or name.endswith("/"):
                continue

            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise RuntimeError(f"Unsafe ZIP symlink blocked: {name}")

            if not is_safe_zip_name(name):
                raise RuntimeError(f"Unsafe ZIP entry blocked: {name}")

            total_uncompressed += member.file_size
            if total_uncompressed > MAX_ZIP_UNCOMPRESSED_BYTES:
                raise RuntimeError("ZIP uncompressed size limit exceeded")

            normalized = name.replace("\\", "/")
            target = (dest / Path(normalized)).resolve()

            try:
                target.relative_to(dest_resolved)
            except ValueError as exc:
                raise RuntimeError(f"Unsafe ZIP entry blocked: {name}") from exc

            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst)


def recon_root_score(path: Path) -> int:
    score = 0
    if (path / ".target.env").is_file():
        score += 5
    if (path / "summary.md").is_file():
        score += 4
    if (path / "scans").is_dir():
        score += 3
    if (path / "enum").is_dir():
        score += 3
    if (path / "scans" / "tcp-services.txt").is_file():
        score += 2
    if (path / "scans" / "port-summary.md").is_file():
        score += 2
    return score


def find_recon_root(root: Path) -> Path:
    if recon_root_score(root) > 0:
        return root

    candidates = [p for p in root.rglob("*") if p.is_dir()]
    best = root
    best_score = 0

    for candidate in candidates:
        try:
            depth = len(candidate.relative_to(root).parts)
        except ValueError:
            continue
        if depth > 3:
            continue

        score = recon_root_score(candidate)
        if score > best_score:
            best = candidate
            best_score = score

    return best


def materialize_input(src: Path) -> tuple[Path, Optional[tempfile.TemporaryDirectory]]:
    src = src.expanduser().resolve()
    if not src.exists():
        raise FileNotFoundError(src)

    if src.is_dir():
        return find_recon_root(src), None

    if zipfile.is_zipfile(src):
        tmp = tempfile.TemporaryDirectory(prefix="analyze-recon-")
        extract_root = Path(tmp.name)
        safe_extract_zip(src, extract_root)
        return find_recon_root(extract_root), tmp

    raise ValueError(f"Unsupported input. Expected folder or ZIP: {src}")


def iter_text_files(root: Path) -> Iterable[Path]:
    skip_dirs = {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        ".next",
        "dist",
        "build",
        "screenshots",
    }
    allowed_suffixes = {
        ".txt",
        ".md",
        ".html",
        ".htm",
        ".json",
        ".xml",
        ".yml",
        ".yaml",
        ".conf",
        ".config",
        ".log",
        ".csv",
        ".ini",
        ".out",
        ".js",
        ".mjs",
        ".map",
        ".env",
    }
    blocked_suffixes = {
        ".pcap",
        ".cap",
        ".zip",
        ".7z",
        ".gz",
        ".tar",
        ".tgz",
        ".exe",
        ".dll",
        ".pdb",
        ".so",
        ".bin",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".pdf",
    }

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        rel = path.relative_to(root)
        rel_posix = rel.as_posix()
        rel_parts = set(rel.parts)

        if rel_parts & skip_dirs:
            continue
        if path.suffix.lower() in blocked_suffixes:
            continue
        if path.stat().st_size > MAX_READ_BYTES * 3:
            continue

        if (
            path.suffix.lower() in allowed_suffixes
            or rel_posix.startswith(("scans/", "enum/", "loot/"))
            or path.name in {".target.env", "package-lock.json", "package.json"}
        ):
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
    service = service.strip()
    version = version.strip()
    proto = proto.strip() or "tcp"

    existing = data.ports.get(num)
    if not existing:
        data.ports[num] = Port(num, service, version, proto)
        return

    if service and not existing.service:
        existing.service = service
    if version and not existing.version:
        existing.version = version
    if proto and not existing.proto:
        existing.proto = proto


def service_text(data: ReconData) -> str:
    parts: list[str] = []
    for port in sorted(data.ports.values(), key=lambda p: (p.proto, p.number)):
        parts.append(f"{port.number}/{port.proto} {port.service} {port.version}")
    parts.extend(sorted(data.technologies))
    parts.extend(sorted(data.endpoints))
    parts.extend(sorted(data.web_urls))
    return "\n".join(parts)


def has_technology(data: ReconData, name: str) -> bool:
    needle = name.lower()
    return needle in service_text(data).lower()


def infer_tech_from_ports(data: ReconData) -> None:
    """Infer possible products from default ports when banners are weak.

    This is deliberately hypothesis-level. It helps the report say
    "possible Zabbix" from 10050/10051 even when Nmap reports tcpwrapped.
    """
    for port_no, rule in PORT_TECH_RULES.items():
        port = data.ports.get(port_no)
        if not port:
            continue

        tech = str(rule.get("tech", "")).strip()
        service = str(rule.get("service", "")).strip()
        detail = str(rule.get("detail", "")).strip()

        if tech:
            data.technologies.add(f"{tech} (port {port_no} heuristic)")
        if service and (not port.service or port.service.lower() in {"unknown", "tcpwrapped", "ppp?"}):
            port.service = service
        if detail and not port.version:
            port.version = detail


def detect_product_versions_from_text(data: ReconData, text: str, rel: str = "") -> None:
    """Extract non-package product versions from banners, HTML, logs, and notes."""
    low_rel = rel.lower()

    for match in ZABBIX_VERSION_RE.finditer(text):
        version = match.group(1).strip().rstrip(".,;:)]}")
        if version:
            data.technologies.add(f"Zabbix {version}")
            add_package(data, "generic", "zabbix", version)

    # Zabbix frontend/API fingerprints often do not expose a version.
    if re.search(r"\bZabbix\b|api_jsonrpc\.php|/zabbix/", text, re.IGNORECASE):
        if not ("nikto" in low_rel and "zabbix" not in text.lower()):
            data.technologies.add("Zabbix")
            add_package(data, "generic", "zabbix", "")


def version_in_range(version: str, affected_range: str) -> Optional[bool]:
    """Best-effort inclusive range check for normal x.y.z versions.

    Returns None when the version/range uses alpha/beta/rc labels or cannot be
    compared safely.
    """
    if not version or "-" not in affected_range:
        return None
    start, end = affected_range.split("-", 1)
    if re.search(r"(?i)(alpha|beta|rc)", version + start + end):
        # Pre-release ordering is easy to get subtly wrong. Keep it manual.
        return None
    try:
        return version_tuple(start) <= version_tuple(version) <= version_tuple(end)
    except Exception:
        return None


def cve_rule_matches(data: ReconData, rule: dict[str, object]) -> tuple[bool, str, str]:
    """Return match status, confidence, and reason for a local CVE hint rule."""
    product = str(rule.get("product", "")).lower()
    haystack = service_text(data).lower()
    hints = [str(h).lower() for h in rule.get("hints", [])]
    version_ranges = [str(r) for r in rule.get("version_ranges", [])]

    product_seen = product and product in haystack
    hint_hits = [h for h in hints if h in haystack]

    detected_versions = []
    for key, versions in data.package_versions.items():
        if product and product in key.lower():
            detected_versions.extend(v for v in versions if v)
    for tech in data.technologies:
        if product and product in tech.lower():
            detected_versions.extend(re.findall(r"\b\d+\.\d+(?:\.\d+)?[0-9A-Za-z.\-+]*", tech))

    for version in sorted(set(detected_versions)):
        checks = [version_in_range(version, r) for r in version_ranges]
        if True in checks:
            return True, "high", f"{rule.get('product')} version {version} falls in affected range"
        if checks and all(c is False for c in checks):
            return False, "low", f"{rule.get('product')} version {version} appears outside configured affected ranges"

    if product_seen and hint_hits:
        return True, str(rule.get("confidence", "medium")), "product and local hints matched; version unknown"
    if len(hint_hits) >= 2:
        return True, "medium", "multiple local hints matched; product/version need confirmation"
    if hint_hits:
        return True, "low", "single weak hint matched; manual confirmation required"

    return False, "low", "no local evidence"


def offline_cve_hints(data: ReconData) -> list[VulnMatch]:
    matches: list[VulnMatch] = []
    for rule in OFFLINE_CVE_RULES:
        matched, confidence, reason = cve_rule_matches(data, rule)
        if not matched:
            continue

        version = ""
        product = str(rule.get("product", ""))
        for key, versions in sorted(data.package_versions.items()):
            if product.lower() in key.lower():
                version = next((v for v in sorted(versions) if v), "")
                break

        matches.append(score_vuln_match(data, VulnMatch(
            source="LOCAL-RULE",
            vuln_id=str(rule.get("id", "unknown")),
            title=str(rule.get("title", "")),
            severity=str(rule.get("severity", "unknown")),
            package=product,
            ecosystem="heuristic",
            version=version or "version unknown",
            confidence=confidence,
            summary=str(rule.get("summary", "")),
            references=[str(r) for r in rule.get("references", [])],
            aliases=[str(rule.get("id", ""))] if rule.get("id") else [],
            reason=reason,
        )))
    return matches


def parse_markdown_port_table_line(data: ReconData, line: str) -> None:
    if not line.strip().startswith("|"):
        return

    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    if not cells or not cells[0].isdigit():
        return

    num = int(cells[0])
    proto = "tcp"
    service = ""
    version = ""

    if len(cells) >= 4 and cells[1].lower() in {"tcp", "udp"}:
        proto = cells[1].lower()
        service = cells[2]
        version = cells[3]
    elif len(cells) >= 3:
        service = cells[1]
        version = cells[2]
    elif len(cells) >= 2:
        service = cells[1]

    add_port(data, num, service, version, proto)


def parse_ports(data: ReconData) -> None:
    candidates = [
        "scans/port-summary.md",
        "summary.md",
        "scans/tcp-services.txt",
        "scans/tcp-full.txt",
        "scans/tcp-aggressive.txt",
        "scans/udp-top100.txt",
    ]

    for rel in candidates:
        text = data.files.get(rel, "")
        if not text:
            continue

        for line in text.splitlines():
            parse_markdown_port_table_line(data, line)

        for num, service, version in PORT_TABLE_RE.findall(text):
            if num.isdigit():
                add_port(data, int(num), service, version)

        for num, proto, service, version in NMAP_OPEN_RE.findall(text):
            if num.isdigit():
                add_port(data, int(num), service, version or "", proto)


def is_scanner_reference_url(url: str) -> bool:
    low = url.lower()
    noisy_domains = (
        "w3.org",
        "schema.org",
        "microsoft.com",
        "robtex.com",
        "github.com",
        "developer.mozilla.org",
        "owasp.org",
        "netsparker.com",
        "nmap.org",
        "nextjs.org",
        "react.dev",
    )
    return any(x in low for x in noisy_domains)


def normalize_url(url: str) -> str:
    return html.unescape(url).rstrip(".,);:]}>'\"")


def is_interesting_path(path: str) -> bool:
    if len(path) < 2 or len(path) > 220:
        return False

    low = path.lower()

    static_prefixes = (
        "/html",
        "/css",
        "/images",
        "/img",
        "/assets",
        "/static",
        "/_next/static",
        "/favicon",
    )
    static_suffixes = (
        ".css",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".map",
    )
    if low.startswith(static_prefixes) or low.endswith(static_suffixes):
        return False

    keywords = (
        "/api",
        "/auth",
        "/login",
        "/logout",
        "/admin",
        "/dashboard",
        "/user",
        "/account",
        "/setting",
        "/profile",
        "/graphql",
        "/swagger",
        "/openapi",
        "/jwks",
        "/token",
        "/oauth",
        "/saml",
        "/upload",
        "/download",
        "/backup",
        "/debug",
        "/dev",
        "/config",
        "/internal",
        "/monitor",
        "/health",
        "/status",
    )
    return any(k in low for k in keywords)


def add_endpoint(data: ReconData, endpoint: str) -> None:
    endpoint = html.unescape(endpoint).strip()
    if not endpoint:
        return

    if endpoint.startswith(("http://", "https://")):
        data.web_urls.add(normalize_url(endpoint))
        return

    if endpoint.startswith("//"):
        return

    if endpoint.startswith("./"):
        endpoint = endpoint[1:]

    if endpoint.startswith("/") and is_interesting_path(endpoint):
        data.endpoints.add(endpoint)


def record_http_headers(data: ReconData, text: str) -> None:
    interesting_headers = {
        "x-powered-by",
        "vary",
        "x-nextjs-cache",
        "x-nextjs-prerender",
        "server",
        "content-type",
        "location",
        "refresh",
        "content-security-policy",
        "x-frame-options",
        "set-cookie",
        "www-authenticate",
    }

    for name, value in HTTP_HEADER_RE.findall(text):
        lname = name.lower().strip()
        if lname in interesting_headers:
            data.http_headers[lname].add(value.strip())


def version_tuple(version: str) -> tuple[int, int, int]:
    nums = re.findall(r"\d+", version.split("+", 1)[0].split("-", 1)[0])
    parts = [int(x) for x in nums[:3]]
    while len(parts) < 3:
        parts.append(0)
    return parts[0], parts[1], parts[2]


def version_lt(version: str, fixed: str) -> bool:
    return version_tuple(version) < version_tuple(fixed)


def nextjs_rsc_vulnerable(version: str) -> Optional[bool]:
    """
    Best-effort check for the React Server Components RCE advisory line
    tracked upstream as CVE-2025-55182. This only handles stable versions
    confidently; canary builds should be reviewed manually.
    """
    low = version.lower()
    if "canary" in low:
        return None

    major, minor, _patch = version_tuple(version)

    fixed_by_line = {
        (15, 0): "15.0.5",
        (15, 1): "15.1.9",
        (15, 2): "15.2.6",
        (15, 3): "15.3.6",
        (15, 4): "15.4.8",
        (15, 5): "15.5.7",
        (16, 0): "16.0.7",
    }

    fixed = fixed_by_line.get((major, minor))
    if fixed:
        return version_lt(version, fixed)

    if major in {15, 16}:
        return None

    return False


def nextjs_middleware_bypass_vulnerable(version: str) -> bool:
    """
    Best-effort check for CVE-2025-29927:
    - 12.x fixed in 12.3.5
    - 13.x fixed in 13.5.9
    - 14.x fixed in 14.2.25
    - 15.x fixed in 15.2.3
    """
    major, _minor, _patch = version_tuple(version)

    if major == 12:
        return version_lt(version, "12.3.5")
    if major == 13:
        return version_lt(version, "13.5.9")
    if major == 14:
        return version_lt(version, "14.2.25")
    if major == 15:
        return version_lt(version, "15.2.3")

    return False


def detect_nextjs_from_text(data: ReconData, text: str, rel: str = "") -> None:
    low = text.lower()
    rel_low = rel.lower()

    if "x-powered-by: next.js" in low or "/_next/static/" in low or "window.next" in low:
        data.technologies.add("Next.js")

    for match in NEXT_WINDOW_RE.finditer(text):
        version = match.group(1).strip()
        data.nextjs_versions.add(version)
        data.technologies.add(f"Next.js {version}")

        snippet = match.group(0)
        if re.search(r"appDir\s*:\s*(?:true|!0|!1|1)", snippet):
            data.nextjs_app_router = True
            data.rsc_indicators.add("window.next appDir enabled")

    for match in NEXT_VERSION_RE.finditer(text):
        version = match.group(1).strip().rstrip(".,;)")
        if "next" in low or "/_next/" in low or "appdir" in low or "next" in rel_low:
            data.nextjs_versions.add(version)
            data.technologies.add(f"Next.js {version}")

    for match in re.finditer(r"""version\s*:\s*["'](1[0-6]\.[0-9]+(?:\.[0-9]+)?[0-9A-Za-z.\-+]*)["']""", text):
        if "next" in low or "/_next/" in rel_low or "appdir" in low:
            version = match.group(1).strip()
            data.nextjs_versions.add(version)
            data.technologies.add(f"Next.js {version}")

    if re.search(r"""appDir\s*:\s*(?:true|!0|1)""", text):
        data.nextjs_app_router = True
        data.rsc_indicators.add("appDir enabled")

    for match in REACT_VERSION_RE.finditer(text):
        version = match.group(1).strip().rstrip(".,;)")
        if "react" in low or "react" in rel_low:
            data.react_versions.add(version)
            data.technologies.add(f"React {version}")

    for match in re.finditer(r"""19\.0\.0-rc-[0-9A-Za-z-]+""", text):
        version = match.group(0)
        data.react_versions.add(version)
        data.technologies.add(f"React {version}")

    if re.search(r"^vary:\s*.*\bRSC\b", text, re.IGNORECASE | re.MULTILINE):
        data.rsc_indicators.add("Vary header contains RSC")

    if re.search(r"^content-type:\s*text/x-component", text, re.IGNORECASE | re.MULTILINE):
        data.rsc_indicators.add("text/x-component response")

    if "next-router-state-tree" in low:
        data.rsc_indicators.add("Next-Router-State-Tree observed")

    if "react server component" in low or "react-server-dom" in low:
        data.rsc_indicators.add("React Server Components string observed")

    if "__next_data__" in low:
        data.technologies.add("Next.js")

    for static_path in NEXT_STATIC_RE.findall(text):
        data.js_files.add(html.unescape(static_path))


def collect_nikto_noise(data: ReconData, text: str) -> None:
    if "nikto" not in text.lower() and "vulnerable to cross site scripting" not in text.lower():
        return

    cms_noise = ("post nuke", "postnuke", "drupal", "ez publish", "mywebserver")
    seen = set(data.nikto_likely_false_positives)

    for line in text.splitlines():
        low = line.lower()
        if "vulnerable to cross site scripting" in low and any(x in low for x in cms_noise):
            clean = line.strip()
            if len(clean) > 260:
                clean = clean[:260] + "..."
            if clean not in seen:
                data.nikto_likely_false_positives.append(clean)
                seen.add(clean)


def strong_cms_fingerprint(text: str, cms: str) -> bool:
    low = text.lower()
    cms = cms.lower()

    if cms == "wordpress":
        markers = (
            "wp-content/", "wp-includes/", "wp-json", "generator\" content=\"wordpress",
            "generator' content='wordpress", "wordpress.org", "/wp-login.php", "/xmlrpc.php"
        )
    elif cms == "drupal":
        markers = (
            "drupal-settings-json", "/sites/default/", "/sites/all/", "generator\" content=\"drupal",
            "generator' content='drupal", "drupal.js", "x-drupal-cache", "x-generator: drupal"
        )
    elif cms == "joomla":
        markers = (
            "/media/system/js/", "generator\" content=\"joomla", "generator' content='joomla",
            "joomla!", "/administrator/index.php"
        )
    else:
        return False

    return any(marker in low for marker in markers)


def detect_tech_from_text(data: ReconData, text: str, rel: str = "") -> None:
    rel_low = rel.lower()

    # Scanner findings often contain product names from generic signatures.
    # Do not let Nikto false-positive text pollute the technology list.
    scanner_noise = any(x in rel_low for x in ("nikto", "nuclei")) or (
        "vulnerable to cross site scripting" in text.lower() and any(
            x in text.lower() for x in ("post nuke", "postnuke", "drupal", "ez publish", "mywebserver")
        )
    )

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
        (r"X-Powered-By:\s*Next\.js|/_next/static/|\bNext\.js\b|__NEXT_DATA__", "Next.js"),
        (r"\bJWT\b", "JWT"),
        (r"\bJWE\b", "JWE"),
        (r"\bJWKS\b", "JWKS"),
        (r"\bBearer\b", "Bearer Token"),
        (r"\bWinRM\b|\bwsman\b", "WinRM"),
        (r"\bRDP\b|ms-wbt-server", "RDP"),
        (r"\bGrafana\b", "Grafana"),
        (r"\bJenkins\b", "Jenkins"),
    ]

    for pattern, name in patterns:
        if not re.search(pattern, text, re.IGNORECASE):
            continue

        if name == "pac4j-jwt":
            match = re.search(r"pac4j-jwt/?([0-9.]+)?", text, re.IGNORECASE)
            if match and match.group(1):
                data.technologies.add(f"pac4j-jwt/{match.group(1).rstrip('.,')}")
            else:
                data.technologies.add(name)
        elif name == "OpenSSH":
            match = re.search(r"\bOpenSSH\s+([0-9][^\s]*)", text, re.IGNORECASE)
            data.technologies.add(f"OpenSSH {match.group(1)}" if match else name)
        elif name == "Microsoft SQL Server":
            match = re.search(r"\bMicrosoft SQL Server\s+([0-9][^;\n]*)", text, re.IGNORECASE)
            data.technologies.add(f"Microsoft SQL Server {match.group(1).strip()}" if match else name)
        else:
            data.technologies.add(name)

    # CMS names must be backed by real fingerprints, not scanner signature text.
    if not scanner_noise:
        if strong_cms_fingerprint(text, "wordpress"):
            data.technologies.add("WordPress")
        if strong_cms_fingerprint(text, "drupal"):
            data.technologies.add("Drupal")
        if strong_cms_fingerprint(text, "joomla"):
            data.technologies.add("Joomla")

def looks_like_nextjs(data: ReconData) -> bool:
    tech = " ".join(sorted(data.technologies)).lower()
    return (
        "next.js" in tech
        or bool(data.nextjs_versions)
        or data.nextjs_app_router
        or any("/_next/static/" in js for js in data.js_files)
        or bool(data.rsc_indicators)
    )


def parse_web(data: ReconData) -> None:
    combined_web = []
    for rel, text in data.files.items():
        if rel.startswith("enum/web/") or rel in (
            "summary.md",
            "scans/tcp-services.txt",
            "scans/tcp-aggressive.txt",
        ):
            combined_web.append((rel, text))

    for rel, text in combined_web:
        collect_urls = (
            rel.endswith("live-web-urls.txt")
            or "whatweb" in rel.lower()
            or rel == "summary.md"
            or rel.endswith((".html", ".htm"))
        )

        if collect_urls:
            for url in URL_RE.findall(text):
                url = normalize_url(url)
                low_url = url.lower()

                if is_scanner_reference_url(url):
                    continue
                if re.match(r"^https?://[a-z](?:[#/:?@]|$)", low_url):
                    continue

                data.web_urls.add(url)

        if rel.startswith("enum/web/"):
            for endpoint in API_PATH_RE.findall(text):
                add_endpoint(data, endpoint)

            for endpoint in FETCH_RE.findall(text):
                add_endpoint(data, endpoint)

            for action in FORM_ACTION_RE.findall(text):
                action = html.unescape(action)
                data.forms.add(action)
                add_endpoint(data, action)

            for name in INPUT_RE.findall(text):
                data.inputs.add(html.unescape(name))

            for src in SCRIPT_SRC_RE.findall(text):
                src = html.unescape(src)
                data.js_files.add(src)
                add_endpoint(data, src)

            for href in LINK_HREF_RE.findall(text):
                add_endpoint(data, href)

        record_http_headers(data, text)
        detect_nextjs_from_text(data, text, rel)
        collect_nikto_noise(data, text)
        detect_tech_from_text(data, text, rel)
        detect_product_versions_from_text(data, text, rel)


def normalize_web_ports(data: ReconData) -> None:
    for port in list(data.ports.values()):
        port_s = str(port.number)
        seen_in_url = any(f":{port_s}" in url for url in data.web_urls)

        if seen_in_url or (port.number == 3000 and looks_like_nextjs(data)):
            if not port.service or port.service.lower() in {"ppp?", "unknown", "tcpwrapped"}:
                port.service = "http"

            if looks_like_nextjs(data) and "next.js" not in port.version.lower():
                version = ", ".join(sorted(data.nextjs_versions))
                port.version = f"Next.js {version}".strip()


def parse_smb(data: ReconData) -> None:
    for rel, text in data.files.items():
        if not rel.startswith("enum/smb/") and rel != "summary.md":
            continue

        for line in text.splitlines():
            line_clean = line.strip()
            match = re.match(r"^([A-Za-z0-9_.-]+\$?)\s+(Disk|IPC)\s*(.*)$", line_clean)
            if match and match.group(1).lower() not in {"sharename", "name"}:
                data.smb_shares.add(match.group(1))

        match = re.search(r"\(name:([^)]+?)\)\s+\(domain:([^)]+?)\)", text, re.IGNORECASE)
        if match:
            data.computer = data.computer or match.group(1).strip()
            data.domain = data.domain or match.group(2).strip()

        match = re.search(r"Domain Name:\s*([A-Za-z0-9_.-]+)", text)
        if match:
            data.domain = data.domain or match.group(1).lower()


def parse_ad_dns_ldap(data: ReconData) -> None:
    for rel, text in data.files.items():
        if not (
            rel.startswith(("enum/ldap/", "enum/dns/"))
            or rel in ("summary.md", "scans/tcp-services.txt", "scans/tcp-aggressive.txt")
        ):
            continue

        for nc in re.findall(r"namingcontexts?:\s*([^\n\r]+)", text, re.IGNORECASE):
            data.naming_contexts.add(nc.strip())

        match = re.search(r"DNS_Domain_Name:\s*([A-Za-z0-9_.-]+)", text)
        if match:
            data.domain = data.domain or match.group(1).strip()

        match = re.search(r"DNS_Computer_Name:\s*([A-Za-z0-9_.-]+)", text)
        if match:
            data.computer = data.computer or match.group(1).strip()

        match = re.search(r"Domain:\s*([A-Za-z0-9_.-]+)", text)
        if match:
            data.domain = data.domain or match.group(1).strip()

        match = re.search(r"ldapServiceName:\s*([^:\s]+):([^@\s]+)@", text, re.IGNORECASE)
        if match:
            data.domain = data.domain or match.group(1).strip()
            data.computer = data.computer or match.group(2).replace("$", "").strip()


def parse_interesting(data: ReconData) -> None:
    lines = []
    seen = set()

    for rel, text in data.files.items():
        if rel == "enum/interesting-grep.txt":
            candidates = text.splitlines()
        elif rel.startswith(("loot/", "enum/")):
            candidates = [
                line
                for line in text.splitlines()
                if re.search(r"password|passwd|pwd|secret|token|apikey|api_key|connection|string|credential", line, re.I)
            ]
        else:
            continue

        for line in candidates:
            line = line.strip()
            if not line or "enum/interesting-grep.txt:enum/interesting-grep.txt" in line:
                continue
            if len(line) > 300:
                line = line[:300] + "..."
            if line not in seen:
                lines.append(line)
                seen.add(line)

    data.interesting_lines = lines[:100]




def add_package(data: ReconData, ecosystem: str, name: str, version: str = "") -> None:
    ecosystem = ecosystem.strip()
    name = name.strip()
    version = str(version).strip().lstrip("v")
    if not ecosystem or not name:
        return
    key = f"{ecosystem}:{name}"
    if version:
        data.package_versions[key].add(version)
    else:
        data.package_versions[key].add("")


def parse_package_files(data: ReconData) -> None:
    """Extract package/version facts from recovered source/lock files.

    This is intentionally conservative. It does not try to resolve semver ranges; it
    only records exact versions where the recon output contains them.
    """
    for rel, text in data.files.items():
        name = Path(rel).name.lower()
        if name == "package.json":
            try:
                obj = json.loads(text)
            except Exception:
                continue
            for block in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                deps = obj.get(block, {})
                if isinstance(deps, dict):
                    for pkg, ver in deps.items():
                        ver = str(ver).strip().lstrip("^~>=< ")
                        if re.match(r"\d+\.\d+", ver):
                            add_package(data, "npm", pkg, ver)
        elif name in {"package-lock.json", "npm-shrinkwrap.json"}:
            try:
                obj = json.loads(text)
            except Exception:
                continue
            packages = obj.get("packages", {})
            if isinstance(packages, dict):
                for pkg_path, meta in packages.items():
                    if not isinstance(meta, dict):
                        continue
                    version = str(meta.get("version", "")).strip()
                    if not version:
                        continue
                    if pkg_path.startswith("node_modules/"):
                        pkg = pkg_path[len("node_modules/"):]
                        add_package(data, "npm", pkg, version)
            deps = obj.get("dependencies", {})
            if isinstance(deps, dict):
                for pkg, meta in deps.items():
                    if isinstance(meta, dict) and meta.get("version"):
                        add_package(data, "npm", pkg, str(meta["version"]))
        elif name == "requirements.txt":
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"([A-Za-z0-9_.\-]+)==([A-Za-z0-9_.!+\-]+)", line)
                if m:
                    add_package(data, "PyPI", m.group(1), m.group(2))
        elif name == "composer.lock":
            try:
                obj = json.loads(text)
            except Exception:
                continue
            for block in ("packages", "packages-dev"):
                for meta in obj.get(block, []) if isinstance(obj.get(block, []), list) else []:
                    if isinstance(meta, dict) and meta.get("name") and meta.get("version"):
                        add_package(data, "Packagist", str(meta["name"]), str(meta["version"]).lstrip("v"))
        elif name == "go.mod":
            for line in text.splitlines():
                line = line.strip()
                m = re.match(r"([A-Za-z0-9_.\-/]+)\s+v([0-9][A-Za-z0-9_.+\-]*)", line)
                if m and not line.startswith("module "):
                    add_package(data, "Go", m.group(1), m.group(2))

    # Add high-confidence packages detected from banners/client bundles.
    for v in data.nextjs_versions:
        add_package(data, "npm", "next", v)
    for v in data.react_versions:
        add_package(data, "npm", "react", v)
    if data.nextjs_versions and data.react_versions:
        # The exact react-server-dom-webpack version is often not visible in the
        # browser bundle. Record it without a version so NVD keyword search can
        # still consider the technology, while OSV exact matching will skip it.
        add_package(data, "npm", "react-server-dom-webpack", "")

    # Generic service/product candidates inferred from ports or banners.
    # They are useful for NVD keyword research and local CVE hint rules.
    if has_technology(data, "zabbix"):
        add_package(data, "generic", "zabbix", "")
    if has_technology(data, "teamcity"):
        add_package(data, "generic", "teamcity", "")
    if has_technology(data, "jenkins"):
        add_package(data, "generic", "jenkins", "")
    if has_technology(data, "grafana"):
        add_package(data, "generic", "grafana", "")


def cache_load(path: Path) -> dict:
    try:
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return {}


def cache_save(path: Path, cache: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache, indent=2, sort_keys=True), encoding="utf-8")


def http_json(method: str, url: str, payload: Optional[dict] = None, headers: Optional[dict] = None, timeout: int = 20) -> dict:
    headers = dict(headers or {})
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    headers.setdefault("User-Agent", "htb-recon-analyzer/1.0")
    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="ignore"))


def as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def first_text(value, limit: int = 180) -> str:
    if value is None:
        return ""
    text = str(value).strip().replace("\r", " ").replace("\n", " ")
    text = re.sub(r"\s+", " ", text)
    return text[:limit]


def severity_rank(severity: str) -> int:
    s = (severity or "").lower()
    if "critical" in s or "10." in s or s.startswith("10"):
        return 0
    if "high" in s or re.search(r"\b[789](?:\.\d+)?\b", s):
        return 1
    if "medium" in s or re.search(r"\b[456](?:\.\d+)?\b", s):
        return 2
    if "low" in s or re.search(r"\b[123](?:\.\d+)?\b", s):
        return 3
    return 4


def extract_reference_urls(value) -> list[str]:
    refs: list[str] = []

    if isinstance(value, dict):
        if "references" in value:
            return extract_reference_urls(value.get("references"))
        if "referenceData" in value:
            return extract_reference_urls(value.get("referenceData"))
        if value.get("url"):
            refs.append(str(value["url"]))
        return refs

    for item in as_list(value):
        if isinstance(item, dict):
            if item.get("url"):
                refs.append(str(item["url"]))
            elif "referenceData" in item or "references" in item:
                refs.extend(extract_reference_urls(item))
        elif isinstance(item, str) and item.startswith(("http://", "https://")):
            refs.append(item)

    out = []
    seen = set()
    for ref in refs:
        if ref not in seen:
            out.append(ref)
            seen.add(ref)
    return out


def extract_osv_severity(vuln: dict) -> str:
    values: list[str] = []

    dbs = vuln.get("database_specific")
    if isinstance(dbs, dict):
        sev = dbs.get("severity") or dbs.get("cvss_severity")
        if sev:
            values.append(str(sev))

    for sev_entry in as_list(vuln.get("severity")):
        if isinstance(sev_entry, dict):
            score = sev_entry.get("score")
            typ = sev_entry.get("type")
            if score and typ:
                values.append(f"{typ} {score}")
            elif score:
                values.append(str(score))
            elif sev_entry.get("severity"):
                values.append(str(sev_entry["severity"]))
        elif sev_entry:
            values.append(str(sev_entry))

    # GitHub-originated OSV records often expose severity only in affected.database_specific.
    for affected in as_list(vuln.get("affected")):
        if isinstance(affected, dict):
            dbs = affected.get("database_specific")
            if isinstance(dbs, dict) and dbs.get("severity"):
                values.append(str(dbs["severity"]))

    if not values:
        return "unknown"

    # Prefer named severities over raw vectors where available.
    named = [v for v in values if re.fullmatch(r"(?i)(critical|high|medium|low|moderate)", v.strip())]
    return (named[0] if named else values[0]).upper()


def extract_osv_title(vuln: dict) -> str:
    candidates = [
        vuln.get("summary"),
        vuln.get("details"),
    ]
    dbs = vuln.get("database_specific")
    if isinstance(dbs, dict):
        candidates.extend([dbs.get("title"), dbs.get("name")])

    for candidate in candidates:
        text = first_text(candidate, 180)
        if text:
            return text
    return ""


def enrich_osv_vuln(vuln: dict, cache: dict, timeout: int = 20) -> dict:
    vuln_id = vuln.get("id")
    if not vuln_id:
        return vuln

    # Batch OSV responses sometimes omit summary/severity/reference details.
    # Fetch the canonical record once and cache it.
    needs_detail = not extract_osv_title(vuln) or extract_osv_severity(vuln) == "unknown" or not extract_reference_urls(vuln.get("references"))
    if not needs_detail:
        return vuln

    cache_key = f"osv-detail:{vuln_id}"
    try:
        detail = cache.get(cache_key)
        if detail is None:
            detail = http_json("GET", OSV_VULN_URL.format(vuln_id=urllib.parse.quote(vuln_id)), timeout=timeout)
            cache[cache_key] = detail
            time.sleep(0.15)
        if isinstance(detail, dict):
            merged = dict(vuln)
            for key, value in detail.items():
                if key not in merged or not merged[key]:
                    merged[key] = value
            return merged
    except Exception:
        return vuln
    return vuln


def match_text(m: VulnMatch) -> str:
    return " ".join([m.vuln_id, *m.aliases, m.title, m.summary, m.package, m.ecosystem]).lower()


def score_vuln_match(data: ReconData, m: VulnMatch) -> VulnMatch:
    text = match_text(m)
    score = 0
    reasons = []

    if m.source == "OSV" and m.ecosystem and m.package and m.version:
        score += 40
        reasons.append("exact OSV package/version match")
    elif m.source == "NVD":
        score += 15
        reasons.append("NVD keyword match")

    if "critical" in (m.severity or "").lower() or severity_rank(m.severity) == 0:
        score += 25
        reasons.append("critical severity")
    elif severity_rank(m.severity) == 1:
        score += 18
        reasons.append("high severity")

    if looks_like_nextjs(data) and ("next" in text or "react" in text):
        score += 15
        reasons.append("matches detected Next.js/React stack")

    if has_technology(data, "zabbix") and "zabbix" in text:
        score += 20
        reasons.append("matches detected Zabbix candidate")

    if m.source == "LOCAL-RULE":
        score += 20
        reasons.append("local port/service CVE rule matched")

    if data.nextjs_app_router and ("app router" in text or "server components" in text or "rsc" in text):
        score += 20
        reasons.append("App Router/RSC condition is locally confirmed")

    if data.rsc_indicators and ("server components" in text or "rsc" in text or "flight" in text):
        score += 20
        reasons.append("RSC behavior is locally confirmed")

    if any(token in text for token in ("remote code execution", "rce", "code execution", "command execution")):
        score += 18
        reasons.append("RCE/code execution impact")

    if any(token in text for token in ("cross-site scripting", "xss", "denial of service", "dos")):
        score -= 8

    m.relevance = score
    m.reason = "; ".join(reasons)
    return m


def top_vuln_candidates(data: ReconData, limit: int = 8) -> list[VulnMatch]:
    scored = [score_vuln_match(data, m) for m in data.vuln_matches]
    return sorted(scored, key=lambda m: (-m.relevance, severity_rank(m.severity), m.vuln_id))[:limit]


def extract_osv_matches(data: ReconData, response: dict, queries: list[dict], cache: dict, timeout: int = 20) -> list[VulnMatch]:
    out: list[VulnMatch] = []
    results = response.get("results", []) if isinstance(response, dict) else []

    for query, result in zip(queries, results):
        pkg = query.get("package", {}) if isinstance(query, dict) else {}
        ecosystem = pkg.get("ecosystem", "")
        name = pkg.get("name", "")
        version = query.get("version", "") if isinstance(query, dict) else ""

        result = result if isinstance(result, dict) else {}
        for vuln in as_list(result.get("vulns")):
            if not isinstance(vuln, dict):
                continue

            vuln = enrich_osv_vuln(vuln, cache, timeout=timeout)
            aliases = [str(a) for a in as_list(vuln.get("aliases")) if a]
            vuln_id = str(vuln.get("id") or (aliases[0] if aliases else "unknown"))
            refs = extract_reference_urls(vuln.get("references"))
            severity = extract_osv_severity(vuln)
            title = extract_osv_title(vuln)
            summary = first_text(vuln.get("details") or vuln.get("summary") or title, 700)

            out.append(score_vuln_match(data, VulnMatch(
                source="OSV",
                vuln_id=vuln_id,
                title=title,
                severity=severity,
                package=name,
                ecosystem=ecosystem,
                version=version,
                confidence="high",
                summary=summary,
                references=refs[:8],
                aliases=aliases,
            )))
    return out

def run_osv_lookup(data: ReconData, cache: dict, timeout: int = 20) -> list[VulnMatch]:
    queries = []
    for key, versions in sorted(data.package_versions.items()):
        ecosystem, name = key.split(":", 1)
        if ecosystem.lower() == "npm":
            osv_ecosystem = "npm"
        else:
            osv_ecosystem = ecosystem
        for version in sorted(v for v in versions if v):
            queries.append({"package": {"ecosystem": osv_ecosystem, "name": name}, "version": version})

    if not queries:
        return []

    # Keep requests small and cacheable.
    matches: list[VulnMatch] = []
    for idx in range(0, len(queries), 100):
        batch = queries[idx:idx + 100]
        cache_key = "osv:" + json.dumps(batch, sort_keys=True)
        if cache_key in cache:
            response = cache[cache_key]
        else:
            response = http_json("POST", OSV_BATCH_URL, {"queries": batch}, timeout=timeout)
            cache[cache_key] = response
            time.sleep(0.2)
        matches.extend(extract_osv_matches(data, response, batch, cache, timeout=timeout))
    return matches


def nvd_keyword_terms(data: ReconData) -> list[str]:
    terms = []
    for key, versions in sorted(data.package_versions.items()):
        ecosystem, name = key.split(":", 1)
        if ecosystem.lower() == "npm" and name in {"next", "react", "react-server-dom-webpack"}:
            for version in sorted(versions):
                terms.append(f"{name} {version}".strip())
    for tech in sorted(data.technologies):
        low = tech.lower()
        if any(x in low for x in ("next.js", "react ", "openssh", "grafana", "jenkins", "teamcity", "tomcat", "jetty", "wordpress", "drupal", "zabbix", "redis", "elasticsearch", "mongodb")):
            terms.append(tech)
    for key, versions in sorted(data.package_versions.items()):
        ecosystem, name = key.split(":", 1)
        if ecosystem.lower() == "generic" and name in {"zabbix", "teamcity", "jenkins", "grafana"}:
            for version in sorted(versions):
                terms.append(f"{name} {version}".strip())
    # Strong fallback terms for the React/RSC fingerprint without hardcoding a CVE.
    if looks_like_nextjs(data) and (data.nextjs_app_router or data.rsc_indicators):
        terms.append("React Server Components Next.js App Router remote code execution")
    out = []
    seen = set()
    for t in terms:
        t = re.sub(r"\s+", " ", t).strip()
        if t and t not in seen:
            out.append(t)
            seen.add(t)
    return out[:8]


def extract_nvd_severity(cve: dict) -> str:
    metrics = cve.get("metrics") if isinstance(cve, dict) else {}
    if not isinstance(metrics, dict):
        return "unknown"

    for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in as_list(metrics.get(metric_key)):
            if not isinstance(entry, dict):
                continue
            cvss = entry.get("cvssData") if isinstance(entry.get("cvssData"), dict) else {}
            score = cvss.get("baseScore") or entry.get("baseScore")
            sev = entry.get("baseSeverity") or cvss.get("baseSeverity") or entry.get("severity")
            if sev and score:
                return f"{sev} {score}"
            if sev:
                return str(sev)
            if score:
                return str(score)
    return "unknown"


def extract_nvd_title(cve: dict) -> str:
    descriptions = cve.get("descriptions") if isinstance(cve, dict) else []
    for desc in as_list(descriptions):
        if isinstance(desc, dict) and desc.get("lang") == "en" and desc.get("value"):
            return first_text(desc["value"], 220)
    for desc in as_list(descriptions):
        if isinstance(desc, dict) and desc.get("value"):
            return first_text(desc["value"], 220)
    return ""


def normalize_nvd_items(response) -> list[dict]:
    if isinstance(response, dict):
        raw_items = response.get("vulnerabilities")
        if raw_items is None and response.get("cve"):
            raw_items = [response]
    elif isinstance(response, list):
        raw_items = response
    else:
        raw_items = []

    items: list[dict] = []
    for item in as_list(raw_items):
        if isinstance(item, dict):
            items.append(item)
    return items


def extract_nvd_matches(data: ReconData, response, term: str, max_results: int) -> list[VulnMatch]:
    matches: list[VulnMatch] = []
    for item in normalize_nvd_items(response)[:max_results]:
        cve = item.get("cve") if isinstance(item.get("cve"), dict) else item
        if not isinstance(cve, dict):
            continue

        cve_id = str(cve.get("id") or "unknown")
        title = extract_nvd_title(cve)
        severity = extract_nvd_severity(cve)
        refs = extract_reference_urls(cve.get("references"))

        aliases = []
        if cve_id.startswith("CVE-"):
            aliases.append(cve_id)

        matches.append(score_vuln_match(data, VulnMatch(
            source="NVD",
            vuln_id=cve_id,
            title=title,
            severity=severity,
            package=term,
            ecosystem="keyword",
            version="",
            confidence="medium",
            summary=title,
            references=refs[:8],
            aliases=aliases,
        )))
    return matches

def run_nvd_lookup(data: ReconData, cache: dict, timeout: int = 20, api_key: str = "", max_results: int = 8) -> list[VulnMatch]:
    matches: list[VulnMatch] = []
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    for term in nvd_keyword_terms(data):
        params = {
            "keywordSearch": term,
            "resultsPerPage": str(max_results),
        }
        url = NVD_CVE_URL + "?" + urllib.parse.urlencode(params)
        cache_key = "nvd:" + term
        if cache_key in cache:
            response = cache[cache_key]
        else:
            response = http_json("GET", url, headers=headers, timeout=timeout)
            cache[cache_key] = response
            time.sleep(0.7 if api_key else 6.2)  # NVD public rate limit is stricter without an API key.
        matches.extend(extract_nvd_matches(data, response, term, max_results))
    return matches


def dedupe_vuln_matches(matches: list[VulnMatch]) -> list[VulnMatch]:
    merged: dict[tuple[str, str, str, str], VulnMatch] = {}

    for m in matches:
        key = (m.source, m.vuln_id, m.package, m.version)
        existing = merged.get(key)
        if not existing:
            merged[key] = m
            continue

        # Keep the richest version of duplicate matches.
        if not existing.title and m.title:
            existing.title = m.title
        if existing.severity == "unknown" and m.severity != "unknown":
            existing.severity = m.severity
        if not existing.summary and m.summary:
            existing.summary = m.summary
        existing.references = list(dict.fromkeys(existing.references + m.references))[:8]
        existing.aliases = list(dict.fromkeys(existing.aliases + m.aliases))[:8]
        existing.relevance = max(existing.relevance, m.relevance)
        if not existing.reason and m.reason:
            existing.reason = m.reason

    out = list(merged.values())

    def rank(m: VulnMatch) -> tuple[int, int, str]:
        return (-m.relevance, severity_rank(m.severity), m.vuln_id)

    return sorted(out, key=rank)



def run_vulnerability_intel(data: ReconData, online: bool, cache_path: Path, timeout: int, nvd_api_key: str, max_results: int) -> None:
    parse_package_files(data)
    matches: list[VulnMatch] = offline_cve_hints(data)
    if not online:
        data.vuln_matches = dedupe_vuln_matches(matches)[:80]
        return
    cache = cache_load(cache_path)
    try:
        matches.extend(run_osv_lookup(data, cache, timeout=timeout))
    except Exception as exc:
        data.vuln_errors.append(f"OSV lookup failed: {exc}")
    try:
        matches.extend(run_nvd_lookup(data, cache, timeout=timeout, api_key=nvd_api_key, max_results=max_results))
    except Exception as exc:
        data.vuln_errors.append(f"NVD lookup failed: {exc}")
    data.vuln_matches = dedupe_vuln_matches(matches)[:80]
    try:
        cache_save(cache_path, cache)
    except Exception as exc:
        data.vuln_errors.append(f"Vulnerability cache save failed: {exc}")

def load_recon(root: Path, source: Path) -> ReconData:
    data = ReconData(root=root, source=source)

    for path in iter_text_files(root):
        rel = path.relative_to(root).as_posix()
        data.files[rel] = read_text(path)

    parse_target_env(data)
    parse_ports(data)
    infer_tech_from_ports(data)
    parse_web(data)
    normalize_web_ports(data)
    parse_smb(data)
    parse_ad_dns_ldap(data)
    parse_interesting(data)

    summary = data.files.get("summary.md", "")

    if not data.ip:
        match = re.search(r"^- IP:\s*(.+)$", summary, re.MULTILINE)
        if match:
            data.ip = match.group(1).strip()

    if not data.host:
        match = re.search(r"^- Hostname:\s*(.+)$", summary, re.MULTILINE)
        if match:
            data.host = match.group(1).strip()

    if not data.box:
        match = re.search(r"^# Recon Summary -\s*(.+)$", summary, re.MULTILINE)
        if match:
            data.box = match.group(1).strip()

    return data


def target_ip(data: ReconData) -> str:
    return data.ip or "<target-ip>"


def target_name(data: ReconData) -> str:
    return data.host or data.ip or "<target>"


def preferred_web_base(data: ReconData) -> str:
    if data.web_urls:
        urls = sorted(data.web_urls)
        for url in urls:
            if ":3000" in url:
                return url.rstrip("/")
        return urls[0].rstrip("/")

    ports = set(data.ports)
    host = target_name(data)

    if 443 in ports:
        return f"https://{host}"
    if 80 in ports:
        return f"http://{host}"
    if 3000 in ports:
        return f"http://{host}:3000"

    for port in sorted(ports):
        service = data.ports[port].service.lower()
        if "http" in service or port in {5000, 8000, 8080, 8443, 9000, 9090, 10000}:
            scheme = "https" if port == 8443 else "http"
            return f"{scheme}://{host}:{port}"

    return f"http://{host}"


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
    if "zabbix" in tech or 10050 in ports or 10051 in ports:
        profiles.append("Monitoring stack / Zabbix candidate")

    return profiles


def build_findings(data: ReconData) -> list[Finding]:
    findings: list[Finding] = []
    ports = set(data.ports)
    tech = " ".join(sorted(data.technologies)).lower()
    endpoints_low = {endpoint.lower() for endpoint in data.endpoints}
    shares_low = {share.lower() for share in data.smb_shares}
    base_url = preferred_web_base(data)

    if not data.ports:
        findings.append(Finding(
            "No open ports parsed from recon output",
            "The analyzer did not parse confirmed open ports. Verify target IP, VPN route, machine state, and whether TCP discovery completed.",
            "high",
            evidence=[
                "No entries matched '<port>/tcp open' or the port summary table.",
                f"Target: {data.ip or data.host or 'unknown'}",
            ],
            commands=[
                f"ip route get {target_ip(data)}",
                f"ping -c 3 {target_ip(data)}",
                f"sudo nmap -p- -sS -Pn --reason --max-retries 3 --min-rate 1000 {target_ip(data)} -oN scans/tcp-full-retry.txt",
                f"sudo nmap -Pn --reason -p 21,22,25,53,80,88,111,135,139,389,443,445,464,593,636,3000,5000,8080,8443,5985,5986 {target_ip(data)} -oN scans/tcp-common-retry.txt",
            ],
        ))

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
            next_chunks = sorted(js for js in data.js_files if "/_next/static/" in js)[:5]
            if next_chunks:
                evidence.append("Next static JS chunks: " + ", ".join(next_chunks))

        matched_text = " ".join((m.vuln_id + " " + m.title + " " + m.summary) for m in data.vuln_matches).lower()
        has_online_rsc_match = bool(data.vuln_matches) and any(
            token in matched_text for token in ("react server components", "react2shell", "cve-2025-55182", "remote code execution")
        ) and (data.nextjs_app_router or data.rsc_indicators)

        if has_online_rsc_match:
            detail = (
                "Next.js App Router/RSC artifacts were detected and online vulnerability intelligence returned relevant RSC/RCE advisory matches. "
                "Treat this as a high-priority manual validation target."
            )
        else:
            detail = (
                "Next.js artifacts were detected. Review framework version, App Router/RSC behavior, middleware, routes, server actions, "
                "and optional OSV/NVD matches before generic brute forcing."
            )

        findings.append(Finding(
            "Next.js / React Server Components attack surface",
            detail,
            "high" if has_online_rsc_match else "medium",
            evidence=evidence or ["Next.js-like artifacts detected"],
            commands=[
                "grep -Rho 'window.next={[^}]*}' enum/web/ 2>/dev/null | sort -u",
                "grep -RhoE '19\\.0\\.0-rc-[0-9A-Za-z-]+' enum/web/ 2>/dev/null | sort -u",
                f"curl -i '{base_url}/' -H 'RSC: 1'",
                f"curl -i '{base_url}/?_rsc=test'",
                "grep -RniE 'server action|server function|use server|react-server-dom|Next-Router-State-Tree|x-action|_rsc|appDir' enum/web/",
            ],
        ))

        if any(("29927" in m.vuln_id or "middleware" in (m.title + " " + m.summary).lower() or "subrequest" in (m.title + " " + m.summary).lower()) for m in data.vuln_matches):
            findings.append(Finding(
                "Next.js middleware authorization-bypass candidate",
                "The detected Next.js version is in a range where middleware-based authorization bypass should be tested if protected routes such as /admin or /dashboard exist.",
                "medium",
                evidence=["Next.js version(s): " + ", ".join(sorted(data.nextjs_versions))],
                commands=[
                    f"for p in admin dashboard login internal monitor monitoring api/status api/health; do echo ===== /$p =====; curl -s -i '{base_url}/'$p | head -n 25; done",
                    f"curl -i '{base_url}/admin' -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware'",
                ],
            ))

    if data.vuln_matches:
        top = data.vuln_matches[:10]
        findings.append(Finding(
            "Online vulnerability intelligence matches",
            "OSV/NVD returned vulnerability records for detected packages or technology keywords. Treat exact package-version OSV matches as stronger than NVD keyword matches.",
            "high",
            evidence=[f"{m.source}: {m.vuln_id} | {m.severity} | {m.package} {m.version} | {m.title}" for m in top],
            commands=[
                "Review the Vulnerability Intelligence section in this report.",
                "Prefer exact OSV package/version matches over broad NVD keyword hits.",
            ],
        ))

    if has_technology(data, "zabbix"):
        zabbix_ports = [p for p in (10050, 10051) if p in ports]
        zabbix_versions = sorted(
            v for key, versions in data.package_versions.items()
            if "zabbix" in key.lower()
            for v in versions
            if v
        )
        evidence = []
        if zabbix_ports:
            evidence.append("Zabbix default port(s): " + ", ".join(str(p) for p in zabbix_ports))
        if zabbix_versions:
            evidence.append("Zabbix version(s): " + ", ".join(zabbix_versions))
        evidence.extend(t for t in sorted(data.technologies) if "zabbix" in t.lower())

        findings.append(Finding(
            "Possible Zabbix exposure / CVE research candidate",
            "Zabbix was inferred from default ports, banners, paths, or text fingerprints. This is enough to trigger Zabbix-specific enumeration and CVE research, but not enough to claim vulnerability without version and access validation.",
            "high" if zabbix_versions else "medium",
            evidence=evidence or ["Zabbix technology candidate detected"],
            commands=[
                f"nmap -sT -sV -sC -p10050,10051 --version-all {target_name(data)}",
                f"for p in zabbix api_jsonrpc.php zabbix/api_jsonrpc.php zabbix/index.php; do echo ===== /$p =====; curl -s -i '{base_url}/'$p | head -n 40; done",
                f"zabbix_get -s {target_ip(data)} -p 10050 -k agent.version",
                f"zabbix_get -s {target_ip(data)} -p 10050 -k system.hostname",
                "grep -RniE 'zabbix|api_jsonrpc|10050|10051|CVE-2024-22120' .",
                "Search terms: Zabbix CVE-2024-22120 affected versions exploit requirements",
            ],
        ))

    if data.nikto_likely_false_positives and looks_like_nextjs(data):
        findings.append(Finding(
            "Likely Nikto CMS/XSS false positives",
            "Nikto reported old CMS XSS signatures, but the app fingerprints as Next.js. Treat these as low-confidence noise unless reflection is proven in this app.",
            "low",
            evidence=data.nikto_likely_false_positives[:6],
            commands=[
                "grep -RniE 'vulnerable to Cross Site Scripting|Post Nuke|Drupal|eZ publish|MyWebServer' enum/web/nikto-*",
                "Manually verify reflection before documenting XSS as a finding.",
            ],
        ))

    if {53, 88, 389, 445}.issubset(ports) or "active directory" in tech:
        findings.append(Finding(
            "Windows AD/DC-style attack surface",
            "DNS, Kerberos, LDAP, and SMB are exposed. Treat this as an Active Directory target and prioritize domain enumeration.",
            "high",
            evidence=[
                f"Ports: {', '.join(str(p) for p in sorted(ports & {53, 88, 389, 445, 464, 636, 3268, 3269}))}",
                f"Domain: {data.domain or data.host or 'unknown'}",
                f"Computer: {data.computer or 'unknown'}",
            ],
            commands=[
                f"netexec smb {target_ip(data)} -u guest -p '' --shares",
                f"ldapsearch -x -H ldap://{target_ip(data)} -s base namingcontexts",
                f"nxc ldap {target_ip(data)} -u guest -p '' --users",
            ],
        ))

    if 445 in ports and data.smb_shares:
        shares = sorted(data.smb_shares)
        default_shares = {"admin$", "c$", "ipc$", "netlogon", "sysvol"}
        non_default = [s for s in shares if s.lower() not in default_shares]

        commands = [f"smbclient -L //{target_ip(data)} -U '%'"]
        for share in non_default:
            commands.append(f"smbclient //{target_ip(data)}/{share} -U '%'")

        findings.append(Finding(
            "SMB share enumeration produced share names",
            "SMB shares were enumerated. Review non-default shares first.",
            "high" if non_default else "medium",
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
                "mkdir -p loot/software && cd loot/software",
                f"smbclient //{target_ip(data)}/software$ -U '%' -c 'recurse ON; prompt OFF; mget *'",
                "find . -type f",
                "grep -RniE \"password|user|uid|pwd|server|sql|connection|string\" .",
            ],
        ))

    if 1433 in ports or 6520 in ports or "sql server" in tech:
        port = 6520 if 6520 in ports else 1433
        findings.append(Finding(
            "MSSQL service exposed",
            "MSSQL is exposed. Look for credentials in SMB shares, configs, source files, or notes, then test SQL authentication and linked servers.",
            "high",
            evidence=[f"Port {port}", *[t for t in sorted(data.technologies) if "SQL Server" in t]],
            commands=[
                f"netexec mssql {target_ip(data)} --port {port} -u <user> -p '<password>'",
                f"impacket-mssqlclient '<domain>/<user>:<password>@{target_name(data)}' -p {port} -windows-auth",
                "select @@version;",
                "select suser_name();",
                "select name from sys.servers;",
            ],
        ))

    if 5985 in ports or 5986 in ports:
        findings.append(Finding(
            "WinRM exposed",
            "WinRM is available. Any recovered domain credentials should be tested for remote shell access.",
            "high",
            evidence=[f"Port {'5985' if 5985 in ports else '5986'}"],
            commands=[
                f"netexec winrm {target_ip(data)} -u <user> -p '<password>'",
                f"evil-winrm -i {target_name(data)} -u <user> -p '<password>'",
            ],
        ))

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

    if "pac4j-jwt" in tech or any("jwks" in e for e in endpoints_low) or "jwe" in tech or "jwt" in tech:
        findings.append(Finding(
            "JWT/JWE/JWKS authentication indicators",
            "JWT/JWE terms or JWKS endpoints were found. Review token handling, exposed keys, role claims, and alg/verification behavior manually.",
            "high" if "pac4j-jwt" in tech else "medium",
            evidence=[
                *[t for t in sorted(data.technologies) if any(k in t.lower() for k in ("jwt", "jwe", "jwks", "pac4j"))],
                *sorted(e for e in data.endpoints if any(k in e.lower() for k in ("jwks", "token", "auth", "login")))[:10],
            ],
            commands=[
                f"curl -s '{base_url}/api/auth/jwks' | jq",
                "grep -RniE \"jwt|jwe|jwks|token|bearer|role|sessionStorage|localStorage\" enum/web/",
                "Search terms: pac4j-jwt <version> JWE JWT auth bypass",
            ],
        ))

    heuristic_ports = []
    for port_no, rule in PORT_TECH_RULES.items():
        if port_no in ports:
            heuristic_ports.append(f"{port_no}/tcp -> {rule.get('tech')} ({rule.get('confidence', 'low')} confidence)")
    if heuristic_ports:
        commands = []
        for port_no, rule in PORT_TECH_RULES.items():
            if port_no not in ports:
                continue
            for command in rule.get("version_commands", []):
                commands.append(str(command).format(target=target_name(data)))
        findings.append(Finding(
            "Default-port technology candidates",
            "One or more open ports map to well-known products. Use these as research hypotheses when service banners are weak, tcpwrapped, or generic.",
            "medium",
            evidence=heuristic_ports[:12],
            commands=commands[:16] or ["Review nmap -sV output and service-specific probes for default-port technologies."],
        ))

    if data.web_urls or data.endpoints or any(p in ports for p in (80, 443, 3000, 5000, 8000, 8080, 8443, 9000, 9090, 10000)):
        findings.append(Finding(
            "Web application artifacts found",
            "Review collected HTML, headers, JavaScript, forms, and API endpoints. This is often more useful than adding more brute force.",
            "medium",
            evidence=[
                f"URLs: {', '.join(sorted(data.web_urls)[:8]) or 'none listed'}",
                f"Endpoints: {', '.join(sorted(data.endpoints)[:12]) or 'none extracted'}",
                f"Forms: {', '.join(sorted(data.forms)[:6]) or 'none extracted'}",
            ],
            commands=[
                "cat enum/web/live-web-urls.txt",
                "grep -RniE \"fetch|axios|/api/|token|auth|login|admin|dashboard|password|secret\" enum/web/",
            ],
        ))

    if 22 in ports:
        findings.append(Finding(
            "SSH exposed",
            "SSH is exposed. Prioritize credential reuse only after finding users/passwords from other services.",
            "low",
            evidence=[f"Version: {data.ports[22].version or data.ports[22].service}"],
            commands=[
                f"netexec ssh {target_ip(data)} -u users.txt -p '<password>'",
                f"ssh <user>@{target_ip(data)}",
            ],
        ))

    if 53 in ports:
        domain = data.host or data.domain or "<domain>"
        findings.append(Finding(
            "DNS service exposed",
            "DNS is exposed. Zone transfer and record enumeration should be reviewed. On AD, DNS records may become useful after credentials are obtained.",
            "medium",
            evidence=[f"Host/domain: {domain}"],
            commands=[
                f"dig @{target_ip(data)} {domain} ANY",
                f"dig axfr @{target_ip(data)} {domain}",
                f"dnsrecon -d {domain} -n {target_ip(data)} -a",
            ],
        ))

    return findings


def cve_search_suggestions(data: ReconData) -> list[str]:
    suggestions = []

    if looks_like_nextjs(data):
        if data.nextjs_versions:
            versions = ", ".join(sorted(data.nextjs_versions))
            suggestions.append(f"Next.js {versions} OSV NVD React Server Components App Router vulnerability check")
            suggestions.append(f"Next.js {versions} middleware authorization bypass OSV NVD")
        else:
            suggestions.append("Next.js App Router React Server Components RSC vulnerability check")

    for tech in sorted(data.technologies):
        low = tech.lower()
        if "pac4j-jwt" in low:
            suggestions.append(f"{tech} JWE JWT authentication bypass CVE")
        elif "jetty" in low:
            suggestions.append(f"{tech} vulnerabilities HTB")
        elif "microsoft sql server" in low:
            suggestions.append(f"{tech} linked server xp_dirtree coercion credentials")
        elif "openssh" in low:
            suggestions.append(f"{tech} privilege escalation CVE check version distro backports")
        elif "zabbix" in low:
            suggestions.append("Zabbix CVE-2024-22120 affected versions exploit requirements api_jsonrpc clientip")
            suggestions.append("Zabbix 10050 10051 agent server version enumeration")
        elif "teamcity" in low:
            suggestions.append(f"{tech} authentication bypass RCE CVE version check")
        elif "grafana" in low:
            suggestions.append(f"{tech} CVE version check default credentials plugins")
        elif "jenkins" in low:
            suggestions.append(f"{tech} RCE script console CVE version check")
        elif ".net message framing" in low:
            suggestions.append(".NET Message Framing WCF localhost service command injection")
        elif "active directory" in low:
            suggestions.append("Active Directory null session SMB LDAP DNS abuse HTB")
        elif "winrm" in low:
            suggestions.append("WinRM valid credentials remote shell evil-winrm")

    out = []
    seen = set()
    for suggestion in suggestions:
        if suggestion not in seen:
            out.append(suggestion)
            seen.add(suggestion)

    return out[:12]


def md_escape_table(s: str) -> str:
    return s.replace("|", "\\|").strip()


def md_code(s: str) -> str:
    return "`" + str(s).replace("`", "\\`").strip() + "`"


def render_report(data: ReconData, findings: list[Finding]) -> str:
    lines: list[str] = []

    lines.append(f"# Recon Analysis - {data.box or data.source.stem}")
    lines.append("")
    lines.append("## Target")
    lines.append("")
    lines.append(f"- Source: {md_code(str(data.source))}")
    lines.append(f"- Workspace: {md_code(str(data.root))}")
    lines.append(f"- Box: {md_code(data.box or 'unknown')}")
    lines.append(f"- IP: {md_code(data.ip or 'unknown')}")
    lines.append(f"- Hostname: {md_code(data.host or 'unknown')}")
    if data.domain:
        lines.append(f"- Domain: {md_code(data.domain)}")
    if data.computer:
        lines.append(f"- Computer: {md_code(data.computer)}")
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
        for port in sorted(data.ports.values(), key=lambda x: (x.proto, x.number)):
            lines.append(
                f"| {port.number} | {md_escape_table(port.proto)} | "
                f"{md_escape_table(port.service)} | {md_escape_table(port.version)} |"
            )
    else:
        lines.append("_No ports parsed._")
    lines.append("")

    lines.append("## Detected Technologies")
    lines.append("")
    if data.technologies:
        for tech in sorted(data.technologies, key=str.lower):
            lines.append(f"- {tech}")
    else:
        lines.append("_No technology indicators parsed._")
    lines.append("")

    if looks_like_nextjs(data):
        lines.append("## Next.js / React Intelligence")
        lines.append("")
        if data.nextjs_versions:
            lines.append("- Next.js version(s): " + ", ".join(md_code(v) for v in sorted(data.nextjs_versions)))
        if data.react_versions:
            lines.append("- React version(s): " + ", ".join(md_code(v) for v in sorted(data.react_versions)))
        lines.append(f"- App Router / appDir detected: {md_code('yes' if data.nextjs_app_router else 'unknown/no')}")
        if data.rsc_indicators:
            lines.append("- RSC indicators:")
            for indicator in sorted(data.rsc_indicators):
                lines.append(f"  - {md_code(indicator)}")
        if data.http_headers:
            lines.append("- High-signal HTTP headers:")
            for header in sorted(data.http_headers):
                values = "; ".join(sorted(data.http_headers[header]))[:220]
                lines.append(f"  - {md_code(f'{header}: {values}')}")
        lines.append("")

    if data.web_urls or data.endpoints or data.js_files or data.forms or data.inputs:
        lines.append("## Web Intelligence")
        lines.append("")
        if data.web_urls:
            lines.append("### URLs")
            for url in sorted(data.web_urls)[:30]:
                lines.append(f"- {md_code(url)}")
            lines.append("")
        if data.js_files:
            lines.append("### JavaScript Files")
            for js_file in sorted(data.js_files)[:30]:
                lines.append(f"- {md_code(js_file)}")
            lines.append("")
        if data.endpoints:
            lines.append("### Extracted Endpoints / Paths")
            for endpoint in sorted(data.endpoints)[:80]:
                lines.append(f"- {md_code(endpoint)}")
            lines.append("")
        if data.forms or data.inputs:
            lines.append("### Forms / Inputs")
            if data.forms:
                lines.append("Forms:")
                for form in sorted(data.forms)[:20]:
                    lines.append(f"- {md_code(form)}")
            if data.inputs:
                lines.append("Inputs:")
                for input_name in sorted(data.inputs)[:30]:
                    lines.append(f"- {md_code(input_name)}")
            lines.append("")

    if data.smb_shares or data.naming_contexts:
        lines.append("## AD / SMB / LDAP Intelligence")
        lines.append("")
        if data.smb_shares:
            lines.append("### SMB Shares")
            default_shares = {"admin$", "c$", "ipc$", "netlogon", "sysvol"}
            for share in sorted(data.smb_shares, key=str.lower):
                marker = " (non-default)" if share.lower() not in default_shares else ""
                lines.append(f"- {md_code(share)}{marker}")
            lines.append("")
        if data.naming_contexts:
            lines.append("### LDAP Naming Contexts")
            for nc in sorted(data.naming_contexts):
                lines.append(f"- {md_code(nc)}")
            lines.append("")

    if data.package_versions:
        lines.append("## Detected Packages / Components")
        lines.append("")
        for key in sorted(data.package_versions)[:80]:
            versions = ", ".join(md_code(v or "version unknown") for v in sorted(data.package_versions[key])[:8])
            lines.append(f"- {md_code(key)}: {versions}")
        lines.append("")

    if data.vuln_matches or data.vuln_errors:
        candidates = top_vuln_candidates(data) if data.vuln_matches else []
        if candidates:
            lines.append("## Top Vulnerability Candidates")
            lines.append("")
            lines.append("| Rank | Source | ID | Severity | Component | Why it matters |")
            lines.append("|---:|---|---|---|---|---|")
            for idx, match in enumerate(candidates, 1):
                component = f"{match.ecosystem}:{match.package} {match.version}".strip()
                why = match.reason or "ranked by exactness, severity, and local evidence"
                lines.append(
                    f"| {idx} | {md_escape_table(match.source)} | {md_escape_table(match.vuln_id)} | "
                    f"{md_escape_table(match.severity)} | {md_escape_table(component)} | {md_escape_table(why[:220])} |"
                )
            lines.append("")

        lines.append("## Vulnerability Intelligence")
        lines.append("")
        if data.vuln_matches:
            lines.append("| Source | ID | Severity | Component | Relevance | Title |")
            lines.append("|---|---|---|---:|---:|---|")
            for match in data.vuln_matches[:40]:
                component = f"{match.ecosystem}:{match.package} {match.version}".strip()
                lines.append(
                    f"| {md_escape_table(match.source)} | {md_escape_table(match.vuln_id)} | "
                    f"{md_escape_table(match.severity)} | {md_escape_table(component)} | {match.relevance} | {md_escape_table((match.title or match.summary)[:140])} |"
                )
            lines.append("")
            lines.append("### Vulnerability References")
            for match in data.vuln_matches[:20]:
                if match.references:
                    alias_text = f" ({', '.join(match.aliases[:3])})" if match.aliases else ""
                    lines.append(f"- {md_code(match.vuln_id + alias_text)}")
                    for ref in match.references[:4]:
                        lines.append(f"  - {md_code(ref)}")
            lines.append("")
        if data.vuln_errors:
            lines.append("### Vulnerability Lookup Errors")
            for err in data.vuln_errors:
                lines.append(f"- {md_code(err)}")
            lines.append("")

    lines.append("## Prioritized Findings and Next Steps")
    lines.append("")
    if not findings:
        lines.append("_No prioritized findings generated._")

    for idx, finding in enumerate(findings, 1):
        lines.append(f"### {idx}. {finding.title}")
        lines.append("")
        lines.append(f"- Confidence: **{finding.confidence.upper()}**")
        lines.append(f"- Detail: {finding.detail}")

        if finding.evidence:
            lines.append("- Evidence:")
            for evidence in finding.evidence:
                if evidence:
                    lines.append(f"  - {md_code(evidence)}")

        if finding.commands:
            lines.append("- Manual verification commands:")
            lines.append("")
            lines.append("```bash")
            for command in finding.commands:
                lines.append(command)
            lines.append("```")

        lines.append("")

    suggestions = cve_search_suggestions(data)
    lines.append("## CVE / Research Search Suggestions")
    lines.append("")
    if suggestions:
        for suggestion in suggestions:
            lines.append(f"- {md_code(suggestion)}")
    else:
        lines.append("_No specific CVE/search suggestions generated._")
    lines.append("")

    if data.interesting_lines:
        lines.append("## Interesting Grep Highlights")
        lines.append("")
        for line in data.interesting_lines[:50]:
            lines.append(f"- {md_code(line)}")
        lines.append("")

    lines.append("## Files Parsed")
    lines.append("")
    for rel in sorted(data.files)[:300]:
        lines.append(f"- {md_code(rel)}")
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
    parser.add_argument("--print", dest="print_report", action="store_true", help="Print report to stdout as well")
    parser.add_argument("--online-vuln-check", action="store_true", help="Query OSV and NVD online for detected packages/technologies")
    parser.add_argument("--vuln-cache", default=str(DEFAULT_VULN_CACHE), help="Local JSON cache for OSV/NVD responses")
    parser.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY", ""), help="Optional NVD API key; defaults to NVD_API_KEY env var")
    parser.add_argument("--vuln-timeout", type=int, default=20, help="Timeout in seconds for vulnerability API calls")
    parser.add_argument("--max-vuln-results", type=int, default=8, help="Max NVD results per keyword query")
    args = parser.parse_args()

    src = Path(args.input)
    is_zip = src.is_file() and zipfile.is_zipfile(src)

    tmp_obj = None
    try:
        root, tmp_obj = materialize_input(src)
        data = load_recon(root, src)
        run_vulnerability_intel(
            data,
            online=args.online_vuln_check,
            cache_path=Path(args.vuln_cache).expanduser().resolve(),
            timeout=args.vuln_timeout,
            nvd_api_key=args.nvd_api_key,
            max_results=args.max_vuln_results,
        )
        findings = build_findings(data)
        report = render_report(data, findings)

        if args.output:
            out_path = Path(args.output).expanduser().resolve()
        else:
            out_path = default_output_path(src.expanduser().resolve(), root, is_zip)

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report, encoding="utf-8")

        print(f"[+] Recon root: {root}")
        print(f"[+] Parsed files: {len(data.files)}")
        print(f"[+] Open ports parsed: {len(data.ports)}")
        print(f"[+] Findings generated: {len(findings)}")
        print(f"[+] Packages/components detected: {len(data.package_versions)}")
        print(f"[+] Vulnerability matches: {len(data.vuln_matches)}")
        print(f"[+] Wrote analysis: {out_path}")

        if args.print_report:
            print()
            print(report)

        return 0

    except Exception as exc:
        print(f"[-] Error: {exc}", file=sys.stderr)
        return 1

    finally:
        if tmp_obj is not None:
            tmp_obj.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
