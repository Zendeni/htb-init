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
import hashlib
import ipaddress
import json
import math
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
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
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
CACHE_TTL_SECONDS = 86400

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
NMAP_OPEN_RE = re.compile(
    r"^(\d+)/(tcp|udp)[^\S\r\n]+open[^\S\r\n]+(\S+)(?:[^\S\r\n]+([^\r\n]*))?\r?$",
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
        "severity": "HIGH",
        "confidence": "medium",
        "impact_keywords": ["remote code execution", "rce", "sql injection", "command execution"],
        "version_ranges": ["6.0.0-6.0.27", "6.4.0-6.4.12", "7.0.0alpha1-7.0.0beta1"],
        "hints": ["zabbix", "10050", "10051", "api_jsonrpc.php", "/zabbix"],
        "title": "Zabbix Server audit log clientip SQL injection / RCE-chain research candidate",
        "summary": "Affected Zabbix Server audit logging may permit SQL injection. Requires a low-privilege account with access to at least one host. Agent or frontend version alone does not establish this Server vulnerability.",
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
    target: str = ""
    evidence: list[dict] = field(default_factory=list)
    status: str = "advisory-candidate"
    prerequisites: list[str] = field(default_factory=list)
    next_test: str = "Confirm affected component, deployment and prerequisites."
    request_method: str = ""
    parameter: str = ""
    parameter_position: str = ""
    session_present: bool = False
    context: dict = field(default_factory=dict)


@dataclass
class ServiceObservation:
    """Host-attributed service facts; access is distinct from a vulnerability."""
    service: str
    kind: str
    target: str
    status: str
    evidence: list[dict] = field(default_factory=list)
    resource: str = ""
    access: str = ""
    platform: str = "unknown"
    domain: str = ""
    hostname: str = ""
    product: str = ""
    version: str = ""
    detail: str = ""
    tls: bool = False


@dataclass
class ReconData:
    root: Path
    source: Path
    box: str = ""
    ip: str = ""
    host: str = ""
    ports: dict[tuple[int, str], Port] = field(default_factory=dict)
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
    scanner_matches: list[VulnMatch] = field(default_factory=list)
    coverage: list[str] = field(default_factory=list)
    package_evidence: dict[str, list[dict]] = field(default_factory=lambda: defaultdict(list))
    scope_include: list[str] = field(default_factory=list)
    scope_exclude: list[str] = field(default_factory=list)
    zabbix_server_versions: set[str] = field(default_factory=set)
    latest_assessment: str = ""
    assessment_status: str = "not-collected"
    assessment_limits: list[str] = field(default_factory=list)
    service_observations: list[ServiceObservation] = field(default_factory=list)


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
        "runs",
        "reports",
        "tools",
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
    proto = proto.strip().lower() or "tcp"
    if not 1 <= num <= 65535 or proto not in {"tcp", "udp"}:
        return

    key = (num, proto)
    existing = data.ports.get(key)
    if not existing:
        data.ports[key] = Port(num, service, version, proto)
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
        port = data.ports.get((port_no, "tcp"))
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
    for match in re.finditer(r"\bZabbix\s+Server[/'\s:-]*(\d+\.\d+(?:\.\d+)?(?:alpha\d+|beta\d+|rc\d+)?)", text, re.I):
        data.zabbix_server_versions.add(match.group(1))

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
    def key(value):
        match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:(alpha|beta|rc)(\d+))?", value, re.I)
        if not match:
            return None
        major, minor, patch, label, sequence = match.groups()
        return (int(major), int(minor), int(patch), {"alpha": 0, "beta": 1, "rc": 2, None: 3}[label.lower() if label else None], int(sequence or 0))
    values = [key(v) for v in (start, version, end)]
    return values[0] <= values[1] <= values[2] if all(v is not None for v in values) else None


def cve_rule_matches(data: ReconData, rule: dict[str, object]) -> tuple[bool, str, str]:
    """Return match status, confidence, and reason for a local CVE hint rule."""
    product = str(rule.get("product", "")).lower()
    haystack = service_text(data).lower()
    hints = [str(h).lower() for h in rule.get("hints", [])]
    version_ranges = [str(r) for r in rule.get("version_ranges", [])]

    product_seen = product and product in haystack
    hint_hits = [h for h in hints if h in haystack]

    detected_versions = []
    if product == "zabbix":
        detected_versions = list(data.zabbix_server_versions)
        if not detected_versions:
            return False, "low", "Zabbix Server version not established; Agent/Frontend versions are insufficient"
    for key, versions in data.package_versions.items():
        if product != "zabbix" and product and product in key.lower():
            detected_versions.extend(v for v in versions if v)
    for tech in data.technologies:
        if product != "zabbix" and product and product in tech.lower():
            detected_versions.extend(re.findall(r"\b\d+\.\d+(?:\.\d+)?[0-9A-Za-z.\-+]*", tech))

    for version in sorted(set(detected_versions)):
        checks = [version_in_range(version, r) for r in version_ranges]
        if True in checks:
            return True, "high", f"{rule.get('product')} version {version} falls in affected range"
    if detected_versions and all(all(version_in_range(v, r) is False for r in version_ranges) for v in detected_versions):
        return False, "low", f"{rule.get('product')} versions are outside configured affected ranges"

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

        evidence, target = [], ""
        if product.lower() == "zabbix":
            version = next((v for v in sorted(data.zabbix_server_versions) if any(version_in_range(v, r) is True for r in rule.get("version_ranges", []))), "")
            for rel, content in data.files.items():
                if not (rel.startswith("scans/") or (rel.startswith("enum/web/") and raw_web_evidence(rel))):
                    continue
                needle = re.search(r"\bZabbix\s+Server[/'\s:-]*" + re.escape(version) + r"\b", content, re.I) if version else None
                if needle:
                    evidence.append(source_evidence(data, rel, needle=needle.group(0)))
                    target = evidence_origin(data, content) if rel.startswith("enum/web/") else data.ip or data.host

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
            evidence=evidence, target=target,
            prerequisites=["A low-privilege Zabbix account with access to at least one host is required; access is not established."],
            next_test="Confirm Zabbix Server build and available account/host permissions against ZBX-24505.",
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
        if re.search(r"appDir\s*:\s*(?:true|!0|1)(?=\s*[,}])", snippet):
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

    if re.search(r"""appDir\s*:\s*(?:true|!0|1)(?=\s*[,}])""", text):
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
        if (rel.startswith("enum/web/") and raw_web_evidence(rel)) or rel in (
            "scans/tcp-services.txt",
            "scans/tcp-aggressive.txt",
        ):
            combined_web.append((rel, text))

    for rel, text in combined_web:
        if rel.startswith("scans/"):
            # NSE script prose is parsed separately as typed findings. Its
            # advisory descriptions are not service/product fingerprints.
            text = "\n".join(line for line in text.splitlines() if NMAP_OPEN_RE.match(line) or line.startswith("Service Info:"))
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

                if in_scope(data, url):
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
        if rel.startswith("enum/web/"):
            local = ReconData(root=data.root, source=data.source)
            detect_nextjs_from_text(local, text, rel)
            target = evidence_origin(data, text)
            for package, versions in (("next", local.nextjs_versions), ("react", local.react_versions)):
                for version in versions:
                    add_package(data, "npm", package, version, evidence=source_evidence(data, rel), target=target, kind="observed")


def normalize_web_ports(data: ReconData) -> None:
    for port in list(data.ports.values()):
        if port.proto != "tcp":
            continue
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
        if not rel.startswith("enum/smb/"):
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
            or rel in ("scans/tcp-services.txt", "scans/tcp-aggressive.txt")
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
        if "assessments/" in rel or rel.endswith(".log") or "templates" in Path(rel).name:
            continue
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




def add_package(data: ReconData, ecosystem: str, name: str, version: str = "", *, evidence: Optional[dict] = None, target: str = "", kind: str = "unattributed") -> None:
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
    if evidence:
        record = {"version": version, "target": target, "kind": kind, "evidence": evidence}
        if record not in data.package_evidence[key]:
            data.package_evidence[key].append(record)


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
            if not isinstance(obj, dict):
                continue
            for block in ("dependencies", "devDependencies", "optionalDependencies"):
                deps = obj.get(block, {})
                if isinstance(deps, dict):
                    for pkg, ver in deps.items():
                        # A manifest constraint is not an observed installed
                        # version. Only a complete exact semver may feed OSV.
                        ver = str(ver).strip()
                        if re.fullmatch(r"v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", ver):
                            add_package(data, "npm", pkg, ver, evidence=source_evidence(data, rel, needle=pkg), kind="dev-declared" if block == "devDependencies" else "declared")
        elif name in {"package-lock.json", "npm-shrinkwrap.json"}:
            try:
                obj = json.loads(text)
            except Exception:
                continue
            if not isinstance(obj, dict):
                continue
            packages = obj.get("packages", {})
            if isinstance(packages, dict):
                for pkg_path, meta in packages.items():
                    if not isinstance(meta, dict):
                        continue
                    version = str(meta.get("version", "")).strip()
                    if not version:
                        continue
                    if pkg_path.startswith("node_modules/") or "/node_modules/" in pkg_path:
                        # npm lockfile keys are installation paths, including
                        # nested dependencies and workspace installations. OSV
                        # needs the registry name (with its optional @scope).
                        pkg = pkg_path.rsplit("node_modules/", 1)[1]
                        add_package(data, "npm", pkg, version, evidence=source_evidence(data, rel, needle=pkg_path), kind="dev-locked" if meta.get("dev") else "locked")
            deps = obj.get("dependencies", {})
            if isinstance(deps, dict):
                for pkg, meta in deps.items():
                    if isinstance(meta, dict) and meta.get("version"):
                        add_package(data, "npm", pkg, str(meta["version"]), evidence=source_evidence(data, rel, needle=pkg), kind="dev-locked" if meta.get("dev") else "locked")
        elif name == "requirements.txt":
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.fullmatch(r"([A-Za-z0-9_.\-]+)==([0-9][A-Za-z0-9_.!+\-]*)(?:\s+#.*)?", line)
                if m:
                    add_package(data, "PyPI", m.group(1), m.group(2), evidence=source_evidence(data, rel, needle=line), kind="declared")
        elif name == "composer.lock":
            try:
                obj = json.loads(text)
            except Exception:
                continue
            if not isinstance(obj, dict):
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
            value = json.loads(path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
    except Exception:
        return {}
    return {}


def cache_save(path: Path, cache: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache, indent=2, sort_keys=True), encoding="utf-8")


def cached_response(cache: dict, key: str):
    item = cache.get(key)
    if not isinstance(item, dict) or not isinstance(item.get("cached_at"), (int, float)):
        return None
    if not 0 <= time.time() - item["cached_at"] <= CACHE_TTL_SECONDS:
        return None
    return item.get("response")


def cache_response(cache: dict, key: str, response) -> None:
    cache[key] = {"cached_at": time.time(), "response": response}


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
    if re.search(r"\bcritical\b", s):
        return 0
    if re.search(r"\bhigh\b", s):
        return 1
    if re.search(r"\b(?:medium|moderate)\b", s):
        return 2
    if re.search(r"\blow\b", s):
        return 3
    score = cvss_score(s)
    return 4 if score is None else 0 if score >= 9 else 1 if score >= 7 else 2 if score >= 4 else 3 if score > 0 else 4


def cvss_score(value: str) -> Optional[float]:
    """Compute supported CVSS 3 base vectors; unknown versions stay unknown."""
    value = value.upper().strip()
    if re.fullmatch(r"(?:10(?:\.0)?|[0-9](?:\.[0-9])?)", value):
        return float(value)
    vector = re.search(r"CVSS:3\.[01]/([^\s]+)", value)
    if not vector:
        return None
    try:
        entries = vector.group(1).split("/")
        metrics = dict(entry.split(":", 1) for entry in entries)
        if len(metrics) != len(entries):
            return None
        scope = metrics["S"]
        if scope not in {"U", "C"}:
            return None
        values = {"H": .56, "L": .22, "N": 0}
        iss = 1 - math.prod(1 - values[metrics[x]] for x in "CIA")
        impact = 6.42 * iss if scope == "U" else 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15
        exploitability = 8.22 * {"N": .85, "A": .62, "L": .55, "P": .2}[metrics["AV"]] * {"L": .77, "H": .44}[metrics["AC"]]
        exploitability *= {"N": .85, "L": .62 if scope == "U" else .68, "H": .27 if scope == "U" else .5}[metrics["PR"]] * {"N": .85, "R": .62}[metrics["UI"]]
        score = min((impact + exploitability) * (1 if scope == "U" else 1.08), 10) if impact > 0 else 0
        return math.ceil((score - 1e-10) * 10) / 10
    except (KeyError, ValueError):
        return None


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
        detail = cached_response(cache, cache_key)
        if detail is None:
            detail = http_json("GET", OSV_VULN_URL.format(vuln_id=urllib.parse.quote(vuln_id)), timeout=timeout)
            cache_response(cache, cache_key, detail)
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
    # Evidence class always dominates severity. A keyword CVE cannot outrank a
    # reproduced endpoint match, regardless of its headline CVSS score.
    score = 1000 if m.status == "scanner-match" else 0
    if m.source == "SERVICE-EVIDENCE":
        score = 600 if m.status == "access-observed" else 100
    reasons = [m.reason] if m.reason else []

    if m.source == "OSV" and m.ecosystem and m.package and m.version:
        score += 200 if m.target and m.evidence else 40
        reasons.append("exact OSV package/version match; deployment and prerequisites require validation")
    elif m.source == "NVD":
        score += 15
        reasons.append("NVD keyword match")

    if "critical" in (m.severity or "").lower() or severity_rank(m.severity) == 0:
        score += 25
        reasons.append("critical severity")
    elif severity_rank(m.severity) == 1:
        score += 18
        reasons.append("high severity")

    if m.source == "LOCAL-RULE":
        score += 150 if m.target and m.evidence and m.confidence == "high" else 20
        reasons.append("local affected-component rule")

    if re.search(r"\b(?:remote code execution|rce|code execution|command execution)\b", text):
        score += 18
        reasons.append("RCE/code execution impact")

    m.relevance = score
    m.reason = "; ".join(dict.fromkeys(part for reason in reasons for part in reason.split("; ")))
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

            provenance = [row for row in data.package_evidence.get(f"{ecosystem}:{name}", []) if row["version"] == version]
            observed = [row for row in provenance if row["kind"] == "observed" and in_scope(data, row["target"])]
            # Source/lockfile evidence proves a dependency declaration, not the
            # version executing at any discovered web endpoint.
            targets = sorted({row["target"] for row in observed}) or [""]
            for target in targets:
                evidence = [row["evidence"] for row in (observed if target else provenance) if not target or row["target"] == target]
                out.append(score_vuln_match(data, VulnMatch(
                source="OSV",
                vuln_id=vuln_id,
                title=title,
                severity=severity,
                package=name,
                ecosystem=ecosystem,
                version=version,
                confidence="medium" if target else "low",
                summary=summary,
                references=refs[:8],
                aliases=aliases,
                target=target, evidence=evidence,
                prerequisites=["Confirm the running version, affected feature and advisory prerequisites."],
                reason="Deployed response version observed." if target else "Dependency declaration/lockfile only; deployment is not established.",
            )))
    return out

def run_osv_lookup(data: ReconData, cache: dict, timeout: int = 20) -> list[VulnMatch]:
    queries = []
    for key, versions in sorted(data.package_versions.items()):
        ecosystem, name = key.split(":", 1)
        # Generic banner-derived products are NVD keyword candidates, not
        # packages in an OSV ecosystem. Do not invalidate an otherwise useful
        # batch by mixing them with actual package-manager coordinates.
        if ecosystem.lower() == "generic":
            continue
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
        response = cached_response(cache, cache_key)
        if response is None:
            response = http_json("POST", OSV_BATCH_URL, {"queries": batch}, timeout=timeout)
            cache_response(cache, cache_key, response)
            time.sleep(0.2)
        matches.extend(extract_osv_matches(data, response, batch, cache, timeout=timeout))
    return matches


def nvd_keyword_terms(data: ReconData) -> list[str]:
    terms = []
    # Service banners are research keywords only. A build number does not
    # establish patch level, affected deployment or exploit prerequisites.
    for observation in data.service_observations:
        if observation.kind == "service-fingerprint" and observation.version and re.search(r"\b(?:IIS|SQL Server)\b", observation.product, re.I):
            terms.append(f"{observation.product} {observation.version}")
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
        cache_key = "nvd:" + url
        response = cached_response(cache, cache_key)
        if response is None:
            response = http_json("GET", url, headers=headers, timeout=timeout)
            cache_response(cache, cache_key, response)
            time.sleep(0.7 if api_key else 6.2)  # NVD public rate limit is stricter without an API key.
        matches.extend(extract_nvd_matches(data, response, term, max_results))
    return matches


def dedupe_vuln_matches(matches: list[VulnMatch]) -> list[VulnMatch]:
    merged: dict[tuple[str, str, str, str], VulnMatch] = {}

    for m in matches:
        key = (m.source, m.vuln_id, m.package, m.version, m.target, m.request_method, m.parameter, m.parameter_position)
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
        existing.evidence.extend(e for e in m.evidence if e not in existing.evidence)
        existing.relevance = max(existing.relevance, m.relevance)
        if not existing.reason and m.reason:
            existing.reason = m.reason

    out = list(merged.values())

    def rank(m: VulnMatch) -> tuple[int, int, str]:
        return (-m.relevance, severity_rank(m.severity), m.vuln_id)

    return sorted(out, key=rank)



def run_vulnerability_intel(data: ReconData, online: bool, cache_path: Path, timeout: int, nvd_api_key: str, max_results: int) -> None:
    parse_package_files(data)
    matches: list[VulnMatch] = list(data.scanner_matches) + offline_cve_hints(data)
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

def raw_web_evidence(rel: str) -> bool:
    """Only captured responses/discovery output may supply technology facts."""
    low = rel.lower()
    name = Path(low).name
    return not (
        "/assessments/" in low or "/runs/" in low
        or any(token in name for token in ("nuclei", "nikto", "templates", "report", "overview", "summary", "technology-profile", "interesting-grep"))
        or low.endswith((".log", ".jsonl", ".md"))
    )


def source_evidence(data: ReconData, rel: str, line: int = 1, needle: str = "", locator: str = "") -> dict:
    content = data.files.get(rel, "")
    if needle:
        line = next((i for i, value in enumerate(content.splitlines(), 1) if needle in value), line)
    return {"path": rel, "line": line, "locator": locator,
            "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest()}


def scope_host(value: str) -> str:
    try:
        if "://" in value:
            return (urllib.parse.urlsplit(value).hostname or "").lower().rstrip(".")
        return value.strip().strip("[]").lower().rstrip(".")
    except ValueError:
        return ""


def in_scope(data: ReconData, target: str) -> bool:
    host = scope_host(target)
    if not host:
        return False
    def matches(entry: str) -> bool:
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return host == scope_host(entry)
    include = data.scope_include or [v for v in (data.ip, data.host) if v]
    return any(matches(v) for v in include) and not any(matches(v) for v in data.scope_exclude)


def initialize_scope(data: ReconData) -> None:
    if "scope.json" in data.files:
        try:
            scope = json.loads(data.files["scope.json"])
            if not isinstance(scope, dict) or not isinstance(scope.get("include"), list) or not isinstance(scope.get("exclude", []), list):
                raise ValueError("include/exclude must be arrays")
            if not all(isinstance(v, str) and v for v in scope["include"] + scope.get("exclude", [])):
                raise ValueError("scope entries must be nonempty strings")
            # An explicit empty scope must not silently fall back to target metadata.
            data.scope_include = scope["include"] or ["<empty-scope>"]
            data.scope_exclude = scope.get("exclude", [])
        except (ValueError, TypeError):
            data.scope_include = ["<invalid-scope>"]
            data.coverage.append("Invalid scope.json: no attack routes can be attributed safely.")
    else:
        data.scope_include = [v for v in (data.ip, data.host) if v]
    if not data.scope_include:
        data.coverage.append("Target scope is missing; findings cannot be promoted to attack routes.")


def evidence_origin(data: ReconData, text: str) -> str:
    # A recorded response URL is stronger than hyperlinks in its body. Never
    # attach an unattributed JS bundle to one of several discovered applications.
    recorded = re.findall(r"(?im)^(?:URL|Target|Request URL):\s*(https?://\S+)", text)
    def origins(values):
        found = set()
        for url in values:
            if in_scope(data, url):
                parsed = urllib.parse.urlsplit(url)
                found.add(f"{parsed.scheme}://{parsed.netloc}")
        return found
    explicit = origins(recorded)
    if len(explicit) == 1:
        return next(iter(explicit))
    if explicit:
        return ""
    # Fallback is safe only when the current discovery set has a single origin.
    known = origins(data.web_urls)
    return next(iter(known)) if len(known) == 1 else ""


def parse_collection_status(data: ReconData) -> None:
    try:
        status = json.loads(data.files.get("run-status.json", "{}"))
    except (ValueError, TypeError):
        status = {}
    if not isinstance(status, dict) or status.get("status") != "completed":
        data.coverage.append("Collection completeness is unverified or incomplete.")
    if isinstance(status, dict):
        for stage in as_list(status.get("stages")):
            if isinstance(stage, dict) and stage.get("status") not in ("completed", "success", "ok"):
                name = str(stage.get("name") or stage.get("stage") or "collection")
                data.coverage.append(f"{name}: {stage.get('status', 'unknown')}.")


def nuclei_match(data: ReconData, item: dict, rel: str, line: int, locator: str = "") -> Optional[VulnMatch]:
    template = str(item.get("template-id") or item.get("template_id") or "")
    target = str(item.get("matched-at") or item.get("matched_at") or item.get("url") or item.get("endpoint") or "")
    if not template or item.get("matcher-status") is False or not in_scope(data, target):
        return None
    info = item.get("info") if isinstance(item.get("info"), dict) else item
    classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
    aliases = [str(v) for v in as_list(classification.get("cve-id")) if re.fullmatch(r"CVE-\d{4}-\d+", str(v), re.I)]
    evidence = source_evidence(data, rel, line, locator=locator or template)
    request = str(item.get("request") or "")
    method = str(item.get("fuzzing_method") or "").upper()
    if not method:
        request_line = re.match(r"^([A-Z]+)\s+\S+\s+HTTP/", request)
        method = request_line.group(1) if request_line else ""
    method = method if method in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} else ""
    parameter = str(item.get("fuzzing_parameter") or "")
    parameter = parameter[:80] if re.fullmatch(r"[A-Za-z0-9_.\[\]-]+", parameter) else ""
    position = str(item.get("fuzzing_position") or "")
    position = position if position in {"query", "body", "header", "cookie", "path"} else ""
    session_present = bool(re.search(r"(?im)^(?:Authorization|Cookie):", request.split("\r\n\r\n", 1)[0]))
    prerequisites = ["Reproduce the match and rule out a template false positive."]
    if session_present:
        prerequisites.append("Preserve the captured session; required authentication is not established.")
    endpoint = urllib.parse.urlsplit(public_target(target)).path or "/"
    next_test = f"Replay {method + ' ' if method else ''}{endpoint}"
    next_test += f" {position + ' ' if position else ''}field {parameter}" if parameter else " matched input"
    next_test += " against a harmless baseline; compare the response."
    return VulnMatch(
        source="NUCLEI", vuln_id=template, title=first_text(info.get("name") or template, 160),
        severity=str(info.get("severity") or "unknown"), confidence="medium",
        summary=first_text(info.get("description"), 700), aliases=aliases,
        references=extract_reference_urls(info.get("reference")), target=target, evidence=[evidence],
        status="scanner-match", reason="Template matcher reported a hit at this endpoint; manual confirmation remains required.",
        prerequisites=prerequisites, next_test=next_test,
        request_method=method, parameter=parameter, parameter_position=position, session_present=session_present,
    )


def parse_web_assessment(data: ReconData) -> None:
    prefix = "enum/web/assessments/"
    runs = {rel[len(prefix):].split("/", 1)[0] for rel in data.files if rel.startswith(prefix) and "/" in rel[len(prefix):]}
    if not runs:
        data.coverage.append("No current structured web assessment is available.")
        return
    # Run directory names begin with sortable UTC timestamps. Never fall back
    # to an older successful run when the newest attempt is partial or empty.
    pointer_path = prefix + "latest.json"
    if pointer_path in data.files:
        try:
            pointer = json.loads(data.files[pointer_path])
            selected = pointer["run_id"]
            if not isinstance(selected, str) or selected not in runs:
                raise ValueError("missing run")
        except (ValueError, TypeError, KeyError):
            data.coverage.append("Latest web assessment pointer is invalid; older findings were not reused.")
            return
    else:
        selected = max(runs)
        if sum(run[:15] == selected[:15] for run in runs) > 1:
            data.coverage.append("Latest web assessment is ambiguous; same-second runs require latest.json.")
            return
    data.latest_assessment = prefix + selected
    report_path = data.latest_assessment + "/report.json"
    try:
        report = json.loads(data.files.get(report_path, "{}"))
        if not isinstance(report, dict):
            raise ValueError("report is not an object")
    except (ValueError, TypeError):
        report = {}
        data.coverage.append("Current web report is unreadable.")
    data.assessment_status = str(report.get("status", "incomplete"))
    data.assessment_limits = [first_text(item, 700) for item in as_list(report.get("limits")) if isinstance(item, str)]
    if any("unauthenticated" in item.lower() for item in data.assessment_limits):
        data.coverage.append("Known HTTP templates ran without authentication; captured sessions apply to DAST requests.")
    if data.assessment_status != "completed":
        data.coverage.append(f"Current web assessment: {data.assessment_status}.")
    for stage in as_list(report.get("stages")):
        if isinstance(stage, dict) and stage.get("status") != "completed":
            data.coverage.append(f"Web {stage.get('name', 'stage')}: {stage.get('status', 'unknown')} ({stage.get('reason') or stage.get('error') or 'coverage incomplete'}).")
    if not report.get("oast_enabled"):
        data.coverage.append("Blind callback-based SSRF/XXE checks were not enabled.")
    # Read only stage finding files, never inventories, stdout, or report prose.
    raw_paths = sorted(rel for rel in data.files if rel.startswith(data.latest_assessment + "/") and Path(rel).name in {"http.jsonl", "dast.jsonl", "nuclei.jsonl"})
    for rel in raw_paths:
        for line, text in enumerate(data.files[rel].splitlines(), 1):
            if not text.strip():
                continue
            try:
                item = json.loads(text)
                if not isinstance(item, dict):
                    raise ValueError("finding is not an object")
                match = nuclei_match(data, item, rel, line)
                if match:
                    data.scanner_matches.append(score_vuln_match(data, match))
            except (ValueError, TypeError):
                data.coverage.append(f"Unparsed finding at {rel}:{line}.")
    if not raw_paths:
        for index, item in enumerate(as_list(report.get("findings"))):
            if isinstance(item, dict):
                match = nuclei_match(data, item, report_path, 1, f"findings[{index}]")
                if match:
                    data.scanner_matches.append(score_vuln_match(data, match))


def nse_match(data: ReconData, target: str, script: str, output: str, rel: str, line: int, locator: str = "") -> None:
    if not in_scope(data, target):
        return
    aliases = list(dict.fromkeys(re.findall(r"\bCVE-\d{4}-\d+\b", output, re.I)))
    vulnerable = bool(re.search(r"(?im)^\s*(?:State:\s*)?VULNERABLE\s*:?\s*$", output))
    if not aliases and not vulnerable:
        return
    # vulners/vulscan enumerate version-based candidates, not behavior checks.
    status = "scanner-match" if vulnerable and script.lower() not in {"vulners", "vulscan"} else "advisory-candidate"
    if re.search(r"\bNOT VULNERABLE\b", output, re.I):
        return
    severity_match = re.search(r"Risk factor:\s*(CRITICAL|HIGH|MEDIUM|LOW)", output, re.I)
    severity = severity_match.group(1).lower() if severity_match else "unknown"
    match = VulnMatch(source="NMAP-NSE", vuln_id=script, title=f"{script}: {'vulnerable response' if vulnerable else 'version-based CVE candidate'}",
        severity=severity, target=target, aliases=aliases, confidence="medium" if vulnerable else "low", status=status,
        evidence=[source_evidence(data, rel, line, locator=locator or script)],
        reason="NSE reported VULNERABLE." if vulnerable else "NSE CVE listing needs affected-version and deployment validation.",
        prerequisites=["Verify script applicability and reproduce the reported behavior."],
        next_test="Review the NSE output and reproduce its non-destructive validation on this service.")
    data.scanner_matches.append(score_vuln_match(data, match))


def nmap_artifact(rel: str) -> bool:
    return rel.startswith("scans/") or (rel.startswith(("enum/smb/", "enum/ldap/", "enum/rdp/", "enum/mssql/", "enum/winrm/", "enum/kerberos/")) and Path(rel).name.startswith("nmap-"))


def observed_context(text: str) -> dict:
    platform = "Samba" if re.search(r"\bSamba\b", text, re.I) else "Windows" if re.search(r"\bWindows\b", text, re.I) else "unknown"
    def value(pattern):
        match = re.search(pattern + r":\s*([^\r\n;]+)", text, re.I)
        return first_text(match.group(1), 100) if match else ""
    return {"platform": platform, "domain": value(r"(?:DNS_Domain_Name|Domain name|Domain)"),
            "hostname": value(r"(?:DNS_Computer_Name|Computer name|NetBIOS_Computer_Name|FQDN)")}


def record_service_observation(data: ReconData, observation: ServiceObservation) -> None:
    if not in_scope(data, observation.target):
        return
    key = (observation.service, observation.kind, observation.target, observation.resource, observation.status)
    for existing in data.service_observations:
        if key == (existing.service, existing.kind, existing.target, existing.resource, existing.status):
            existing.evidence.extend(row for row in observation.evidence if row not in existing.evidence)
            for attribute in ("domain", "hostname", "product", "version", "detail"):
                if not getattr(existing, attribute):
                    setattr(existing, attribute, getattr(observation, attribute))
            if existing.platform == "unknown":
                existing.platform = observation.platform
            return
    data.service_observations.append(observation)


def service_category(number: int, name: str, product: str = "") -> str:
    value = (name + " " + product).lower()
    # A product family can implement several protocols (e.g. Samba AD).
    # Protocol detection takes precedence over product branding.
    if "kerberos" in name.lower():
        return "kerberos"
    if re.search(r"ms-sql|microsoft sql server", value):
        return "mssql"
    if "ldap" in value:
        return "ldap"
    if re.search(r"microsoft-ds|netbios-ssn|\bsmb\b|samba", value):
        return "smb"
    if "ms-wbt" in value or "terminal services" in value:
        return "rdp"
    if "winrm" in value or "windows remote management" in value:
        return "winrm"
    if "kerberos" in value:
        return "kerberos"
    if re.search(r"\bIIS\b", product, re.I):
        return "http"
    if number in {5985, 5986} and "httpapi" in value:
        return "winrm"
    if name.strip().lower() in {"", "unknown", "tcpwrapped", "msrpc"} and not product:
        return {139: "smb", 445: "smb", 389: "ldap", 636: "ldap", 3268: "ldap", 3269: "ldap", 3389: "rdp", 5985: "winrm", 5986: "winrm", 88: "kerberos", 1433: "mssql"}.get(number, "")
    return ""


def service_ports(data: ReconData, category: str) -> set[int]:
    ports = {port.number for port in data.ports.values() if port.proto == "tcp" and service_category(port.number, port.service, port.version) == category}
    for observation in data.service_observations:
        if observation.service == category:
            number = urllib.parse.urlsplit(observation.target).port
            if number:
                ports.add(number)
    return ports


def service_uses_tls(data: ReconData, number: int) -> bool:
    port = data.ports.get((number, "tcp"))
    if number in {636, 3269, 5986} or (port and (port.service.lower().startswith("ssl/") or port.service.lower() in {"ldaps", "https"})):
        return True
    return any(observed.tls and urllib.parse.urlsplit(observed.target).port == number for observed in data.service_observations)


def observe_nmap_service(data: ReconData, address: str, number: int, protocol: str, service: str, product: str, version: str, rel: str, context: dict) -> None:
    if protocol != "tcp" or not in_scope(data, address):
        return
    category = service_category(number, service, product)
    if not category:
        return
    host = f"[{address}]" if ":" in address else address
    tls = service.lower().startswith("ssl/") or service.lower() in {"ldaps", "https"} or number in {636, 3269, 5986}
    target = f"{'ldaps' if category == 'ldap' and tls else category}://{host}:{number}"
    record_service_observation(data, ServiceObservation(category, "service-fingerprint", target,
        "service-observed" if product and not (category == "winrm" and "httpapi" in product.lower()) else "port-observed", product=product, version=version,
        evidence=[source_evidence(data, rel, locator=f"host[{address}]/port[{number}]/service")], tls=tls, **context))


def administrative_share(name: str) -> bool:
    return name.lower() in {"admin$", "ipc$"} or bool(re.fullmatch(r"[a-zA-Z]\$", name))


def observe_nmap_script(data: ReconData, target: str, script: str, output: str, rel: str, line: int,
                        context: dict, invocation: str = "", locator: str = "") -> None:
    if not in_scope(data, target):
        return
    parsed = urllib.parse.urlsplit(target if "://" in target else "//" + (f"[{target}]" if ":" in target else target))
    host = parsed.hostname or target
    host = f"[{host}]" if ":" in host else host
    evidence = [source_evidence(data, rel, line, locator=locator or script)]
    if script == "smb-enum-shares":
        share, share_host = "", host
        for value in output.splitlines():
            unc = re.match(r"\s*\\\\([^\\]+)\\([^\\:]+):?\s*$", value)
            bare = re.match(r"\s*([A-Za-z0-9_. $-]+):?\s*$", value)
            if unc:
                share_host, share = unc.groups()
            elif bare and bare.group(1).strip():
                share, share_host = bare.group(1).strip(), host
            access = re.match(r"\s*Anonymous access:\s*(READ(?:/WRITE)?|READ ONLY)\s*$", value, re.I)
            if access and share and not administrative_share(share) and in_scope(data, share_host):
                port = parsed.port or 445
                share_host = f"[{share_host}]" if ":" in share_host and not share_host.startswith("[") else share_host
                endpoint = f"smb://{share_host}:{port}/{urllib.parse.quote(share, safe='') }"
                record_service_observation(data, ServiceObservation("smb", "anonymous-share-access", endpoint, "access-observed",
                    resource=share, access=access.group(1).upper(), evidence=evidence, **context))
    if script in {"smb-security-mode", "smb2-security-mode"} and re.search(r"(?:signing[^\r\n]*(?:not required|disabled)|message_signing:\s*disabled)", output, re.I):
        record_service_observation(data, ServiceObservation("smb", "signing-not-required", f"smb://{host}:{parsed.port or 445}",
            "configuration-observed", evidence=evidence, detail="Signing is not required for at least one observed SMB dialect.", **context))
    if script == "ldap-search":
        objects = re.findall(r"(?im)^\s*dn:\s*((?:CN|OU|UID|DC)=[^\r\n]+)", output)
        has_attributes = bool(re.search(r"(?im)^\s*(?:sAMAccountName|objectClass|uid|cn|operatingSystem|userPrincipalName):\s*\S", output))
        if objects and has_attributes:
            # ldap-search can reuse ldap-brute credentials from Nmap's registry.
            # Missing invocation or a credentials file must remain unattributed.
            anonymous = bool(re.search(r"--script(?:=|\s+)[^\r\n]*\bldap-search\b", invocation)) and not re.search(r"ldap\.(?:username|password)|brute|--script-args-file", invocation, re.I)
            status = "access-observed" if anonymous else "authentication-unknown"
            ldap_context = dict(context)
            if not ldap_context["domain"]:
                ldap_context["domain"] = ".".join(re.findall(r"(?:^|,)\s*DC=([^,]+)", objects[0], re.I))
            record_service_observation(data, ServiceObservation("ldap", "anonymous-objects" if anonymous else "directory-objects",
                f"{'ldaps' if parsed.scheme == 'tls' or parsed.port in {636, 3269} else 'ldap'}://{host}:{parsed.port or 389}", status, resource=f"{len(objects)} directory objects", access="anonymous" if anonymous else "unknown",
                evidence=evidence, detail="Directory object attributes were returned; this may be intended public access.", **ldap_context))


def parse_smb_access(data: ReconData) -> None:
    """smbclient -L lists names only; only an explicit access test is a lead."""
    for rel, text in data.files.items():
        if not rel.startswith("enum/smb/") or not re.fullmatch(r"smbmap-null(?:-\d+)?\.txt", Path(rel).name):
            continue
        address, port = "", "445"
        for line, value in enumerate(text.splitlines(), 1):
            match = re.search(r"\bIP:\s*(\[[^]]+\]|[^\s:]+)(?::(\d+))?", value)
            if match:
                address, port = match.group(1).strip("[]"), match.group(2) or "445"
            access = re.match(r"\s*(\S+)\s+(READ ONLY|READ,? WRITE|READ/WRITE|READABLE)\b", value, re.I)
            if access and address and in_scope(data, address) and not administrative_share(access.group(1)):
                share = access.group(1)
                host = f"[{address}]" if ":" in address else address
                peers = [row for row in data.service_observations if scope_host(row.target) == scope_host(address)]
                context = {}
                for key in ("platform", "domain", "hostname"):
                    values = {getattr(row, key) for row in peers if getattr(row, key) not in {"", "unknown"}}
                    context[key] = next(iter(values)) if len(values) == 1 else "unknown" if key == "platform" else ""
                record_service_observation(data, ServiceObservation("smb", "anonymous-share-access",
                    f"smb://{host}:{port}/{urllib.parse.quote(share, safe='')}", "access-observed", resource=share,
                    access=access.group(2).upper(), evidence=[source_evidence(data, rel, line)],
                    detail="Read access observed with the collector's empty-credential SMB probe; guest mapping is possible.", **context))


def parse_nse(data: ReconData) -> None:
    xml_bases = set()
    for rel, text in data.files.items():
        if not nmap_artifact(rel) or not rel.endswith(".xml"):
            continue
        if "<!ENTITY" in text.upper():
            data.coverage.append(f"Rejected XML entities in {rel}.")
            continue
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            data.coverage.append(f"Nmap XML is incomplete or unreadable: {rel}.")
            continue
        xml_bases.add(rel[:-4])
        for host in root.findall("host"):
            addresses = [v.get("addr", "") for v in host.findall("address") if v.get("addrtype") in ("ipv4", "ipv6")]
            address = next((v for v in addresses if in_scope(data, v)), "")
            if not address:
                continue
            url_host = f"[{address}]" if ":" in address else address
            host_text = "\n".join(script.get("output", "") for script in host.findall(".//script"))
            host_text += "\n" + " ".join(" ".join(service.attrib.values()) for service in host.findall("ports/port/service"))
            context = observed_context(host_text)
            invocation = root.get("args", "")
            smb_ports = []
            for candidate in host.findall("ports/port"):
                candidate_service = candidate.find("service")
                if candidate.get("portid", "").isdigit() and candidate.get("protocol") == "tcp" and candidate.find("state") is not None and candidate.find("state").get("state") == "open":
                    name = candidate_service.get("name", "") if candidate_service is not None else ""
                    product = candidate_service.get("product", "") if candidate_service is not None else ""
                    if service_category(int(candidate.get("portid")), name, product) == "smb":
                        smb_ports.append(candidate.get("portid"))
            for port in host.findall("ports/port"):
                if port.find("state") is None or port.find("state").get("state") != "open":
                    continue
                service = port.find("service")
                target = f"{'tls' if service is not None and service.get('tunnel') == 'ssl' else port.get('protocol', 'tcp')}://{url_host}:{port.get('portid', '')}"
                if service is not None and port.get("portid", "").isdigit():
                    service_name = ("ssl/" if service.get("tunnel") == "ssl" else "") + service.get("name", "")
                    add_port(data, int(port.get("portid")), service_name, " ".join(value for value in (service.get("product", ""), service.get("version", "")) if value), port.get("protocol", "tcp"))
                    observe_nmap_service(data, address, int(port.get("portid")), port.get("protocol", "tcp"), service_name, service.get("product", ""), service.get("version", ""), rel, context)
                for script in port.findall("script"):
                    script_id = script.get("id", "unknown")
                    output = script.get("output", "")
                    nse_match(data, target, script_id, output, rel, 1, f"host[{address}]/port[{port.get('portid')}]/script[{script_id}]")
                    observe_nmap_script(data, target, script_id, output, rel, 1, context, invocation, f"host[{address}]/port[{port.get('portid')}]/script[{script_id}]")
            for script in host.findall("hostscript/script"):
                script_id = script.get("id", "unknown")
                target = f"tcp://{url_host}:{smb_ports[0]}" if script_id.startswith("smb") and len(smb_ports) == 1 else address
                nse_match(data, target, script_id, script.get("output", ""), rel, 1, "hostscript")
                observe_nmap_script(data, target, script_id, script.get("output", ""), rel, 1, context, invocation, f"host[{address}]/hostscript[{script_id}]")
    for rel, text in data.files.items():
        if not nmap_artifact(rel) or not rel.endswith(".txt") or rel[:-4] in xml_bases:
            continue
        host, port, script, block, start, smb_ports = "", "", "", [], 1, []
        def flush():
            if script and host:
                script_target = port or host
                if script.startswith("smb") and not port and len(smb_ports) == 1:
                    script_target = f"tcp://{'[' + host + ']' if ':' in host else host}:{smb_ports[0]}"
                nse_match(data, script_target, script, "\n".join(block), rel, start)
                observe_nmap_script(data, script_target, script, "\n".join(block), rel, start, observed_context(""), text.splitlines()[0] if text.startswith("# Nmap") else "")
        for line_no, line in enumerate(text.splitlines(), 1):
            host_match = re.match(r"Nmap scan report for (?:.*\()?([A-Za-z0-9.:_-]+)\)?$", line)
            port_match = NMAP_OPEN_RE.match(line)
            script_match = re.match(r"^\|[_ ]([A-Za-z0-9_-]+):(?:\s*(.*))?$", line)
            if host_match or port_match or script_match:
                flush()
                script, block = "", []
            if host_match:
                host, port, smb_ports = host_match.group(1), "", []
            elif port_match:
                address = f"[{host}]" if ":" in host else host
                port = f"{'tls' if port_match.group(3).startswith('ssl/') else port_match.group(2)}://{address}:{port_match.group(1)}"
                if port_match.group(2) == "tcp" and port_match.group(1) in {"139", "445"}:
                    smb_ports.append(port_match.group(1))
                banner = port_match.group(4) or ""
                version = re.search(r"\b\d+(?:\.\d+){1,3}\b", banner)
                observe_nmap_service(data, host, int(port_match.group(1)), port_match.group(2), port_match.group(3), banner, version.group(0) if version else "", rel, observed_context(banner))
            elif script_match:
                script, block, start = script_match.group(1), [script_match.group(2) or ""], line_no
            elif script and line.startswith("|"):
                block.append(line[1:].lstrip("_ "))
            elif script:
                flush()
                script, block = "", []
            if line.strip() == "Host script results:":
                port = ""
        flush()


def load_recon(root: Path, source: Path) -> ReconData:
    data = ReconData(root=root, source=source)

    for path in iter_text_files(root):
        rel = path.relative_to(root).as_posix()
        data.files[rel] = read_text(path)

    parse_target_env(data)
    initialize_scope(data)
    parse_collection_status(data)
    for rel, text in data.files.items():
        if rel.endswith("live-web-urls.txt") and raw_web_evidence(rel):
            data.web_urls.update(normalize_url(url) for url in URL_RE.findall(text) if in_scope(data, url))
    parse_ports(data)
    infer_tech_from_ports(data)
    parse_web(data)
    normalize_web_ports(data)
    parse_smb(data)
    parse_ad_dns_ldap(data)
    parse_interesting(data)
    parse_web_assessment(data)
    parse_nse(data)
    parse_smb_access(data)

    return data


def target_ip(data: ReconData) -> str:
    return data.ip or "<target-ip>"


def target_name(data: ReconData) -> str:
    return data.host or data.ip or "<target>"


def preferred_web_base(data: ReconData) -> str:
    management_ports = service_ports(data, "winrm")
    urls = [url for url in data.web_urls if in_scope(data, url) and urllib.parse.urlsplit(url).port not in management_ports]
    if urls:
        urls.sort(key=lambda url: (scope_host(url) != scope_host(data.host or data.ip), urllib.parse.urlsplit(url).scheme != "https", len(url), url))
        parsed = urllib.parse.urlsplit(urls[0])
        return f"{parsed.scheme}://{parsed.netloc}"

    tcp_ports = {p.number: p for p in data.ports.values() if p.proto == "tcp"}
    ports = set(tcp_ports)
    host = target_name(data)

    if 443 in ports:
        return f"https://{host}"
    if 80 in ports:
        return f"http://{host}"
    if 3000 in ports:
        return f"http://{host}:3000"

    for port in sorted(ports):
        if port in management_ports:
            continue
        service = tcp_ports[port].service.lower()
        if "http" in service or port in {5000, 8000, 8080, 8443, 9000, 9090, 10000}:
            scheme = "https" if port == 8443 or service.startswith("ssl/") else "http"
            return f"{scheme}://{host}:{port}"

    return f"http://{host}"


def detect_profile(data: ReconData) -> list[str]:
    profiles = []
    ports = {p.number for p in data.ports.values() if p.proto == "tcp"}
    tech = " ".join(sorted(data.technologies) + [row.product for row in data.service_observations]).lower()

    platforms = {observation.platform for observation in data.service_observations}
    banner_text = " ".join(port.version for port in data.ports.values() if port.proto == "tcp").lower()
    if "samba" in banner_text or "Samba" in platforms:
        profiles.append("Samba service fingerprint; Windows is not established")
    elif "Windows" in platforms or "windows" in banner_text or any("windows" in t.lower() for t in data.technologies):
        profiles.append("Windows")
    else:
        profiles.append("Operating system unconfirmed")
    if (service_ports(data, "kerberos") and service_ports(data, "ldap") and service_ports(data, "smb")) or "active directory" in tech:
        profiles.append("Active Directory / directory service candidate")

    if any(p in ports for p in (80, 443, 3000, 5000, 8000, 8080, 8443, 9000, 9090, 10000)) or data.web_urls:
        profiles.append("Web application")
    if service_ports(data, "smb"):
        profiles.append("SMB exposed")
    if service_ports(data, "ldap"):
        profiles.append("LDAP exposed")
    if 88 in ports:
        profiles.append("Kerberos exposed")
    if service_ports(data, "winrm"):
        profiles.append("WinRM exposed")
    if service_ports(data, "mssql"):
        profiles.append("MSSQL exposed")
    if service_ports(data, "rdp"):
        profiles.append("RDP access requires authorized credentials and rights")
    if 9389 in ports or ".net message framing" in tech:
        profiles.append(".NET/ADWS-style service exposed")
    if "zabbix" in tech or 10050 in ports or 10051 in ports:
        profiles.append("Monitoring stack / Zabbix candidate")

    return profiles


def build_findings(data: ReconData) -> list[Finding]:
    findings: list[Finding] = []
    ports = {p.number for p in data.ports.values() if p.proto == "tcp"}
    tech = " ".join(sorted(data.technologies) + [row.product for row in data.service_observations]).lower()
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

        relevant = [m for m in data.vuln_matches if m.source == "OSV" and m.ecosystem.lower() == "npm"
                    and m.package in {"next", "react-server-dom-webpack", "react-server-dom-parcel", "react-server-dom-turbopack"}
                    and m.target and m.evidence and in_scope(data, m.target)]
        has_online_rsc_match = any(re.search(r"\b(?:react server components|react2shell|CVE-2025-55182)\b", match_text(m), re.I) for m in relevant)

        if has_online_rsc_match:
            detail = (
                "A response-attributed framework version has a package-specific RSC advisory match. "
                "Confirm affected deployment features and prerequisites on that same application."
            )
        else:
            detail = (
                "Next.js artifacts were detected. Review framework version, App Router/RSC behavior, middleware, routes, server actions, "
                "and optional OSV/NVD matches before generic brute forcing."
            )

        findings.append(Finding(
            "Next.js / React Server Components attack surface",
            detail,
            "medium",
            evidence=evidence or ["Next.js-like artifacts detected"],
            commands=[
                "grep -Rho 'window.next={[^}]*}' enum/web/ 2>/dev/null | sort -u",
                "grep -RhoE '19\\.0\\.0-rc-[0-9A-Za-z-]+' enum/web/ 2>/dev/null | sort -u",
                f"curl -i '{base_url}/' -H 'RSC: 1'",
                f"curl -i '{base_url}/?_rsc=test'",
                "grep -RniE 'server action|server function|use server|react-server-dom|Next-Router-State-Tree|x-action|_rsc|appDir' enum/web/",
            ],
        ))

        middleware_matches = [m for m in relevant if m.package == "next" and
                              "CVE-2025-29927" in [m.vuln_id, *m.aliases] and nextjs_middleware_bypass_vulnerable(m.version)]
        if middleware_matches:
            findings.append(Finding(
                "Next.js middleware authorization-bypass candidate",
                "A version-specific Next.js advisory match needs validation of middleware-based authorization and affected routes on the attributed endpoint.",
                "medium",
                evidence=[f"{m.target}: Next.js {m.version}, {m.vuln_id}" for m in middleware_matches],
                commands=[
                    f"for p in admin dashboard login internal monitor monitoring api/status api/health; do echo ===== /$p =====; curl -s -i '{base_url}/'$p | head -n 25; done",
                    f"curl -i '{base_url}/admin' -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware'",
                ],
            ))

    if data.vuln_matches:
        top = data.vuln_matches[:10]
        findings.append(Finding(
            "Vulnerability evidence and advisory candidates",
            "Scanner hits, package advisories and keyword candidates have different evidence strengths. Review status, source and prerequisites before treating a candidate as exploitable.",
            "medium",
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

    ldap_ports = service_ports(data, "ldap")
    if (ldap_ports and service_ports(data, "kerberos") and service_ports(data, "smb")) or "active directory" in tech:
        ldap_port = min(ldap_ports) if ldap_ports else None
        ldap_url = f"{'ldaps' if service_uses_tls(data, ldap_port) else 'ldap'}://{target_ip(data)}:{ldap_port}" if ldap_port else "<observed-ldap-endpoint>"
        findings.append(Finding(
            "Directory services / Active Directory evidence",
            "Observed directory-service fingerprints suggest a domain environment. Confirm the host role and access policy; service presence does not establish credentials or privileges.",
            "medium",
            evidence=[
                f"Ports: {', '.join(str(p) for p in sorted(ports & {53, 88, 389, 445, 464, 636, 3268, 3269}))}",
                f"Domain: {data.domain or data.host or 'unknown'}",
                f"Computer: {data.computer or 'unknown'}",
            ],
            commands=[
                f"ldapsearch -x -H '{ldap_url}' -s base namingcontexts",
            ],
        ))

    smb_ports = service_ports(data, "smb")
    smb_port = 445 if 445 in smb_ports else min(smb_ports) if smb_ports else None
    if smb_ports and data.smb_shares:
        shares = sorted(data.smb_shares)
        default_shares = {"admin$", "c$", "ipc$", "netlogon", "sysvol"}
        non_default = [s for s in shares if s.lower() not in default_shares]

        commands = [f"smbclient -L //{target_ip(data)} -p {smb_port} -U '%'"]
        for share in non_default:
            commands.append(f"smbclient '//{target_ip(data)}/{share}' -p {smb_port} -U '%'")

        findings.append(Finding(
            "SMB share enumeration produced share names",
            "SMB shares were enumerated. Review non-default shares first.",
            "medium",
            evidence=[", ".join(shares)],
            commands=commands,
        ))

    if smb_ports and "software$" in shares_low:
        findings.append(Finding(
            "SMB share access review: software$",
            "A software$ share name was returned. Confirm read permission and intended exposure before inspecting any files.",
            "medium",
            evidence=["Share: software$"],
            commands=[
                f"smbclient '//{target_ip(data)}/software$' -p {smb_port} -U '%' -c 'ls'",
            ],
        ))

    mssql_ports = service_ports(data, "mssql")
    if mssql_ports:
        findings.append(Finding(
            "MSSQL service/access candidate",
            "The detected SQL endpoint requires an authorized account and database permissions. A banner or listening port does not establish SQL access or vulnerability.",
            "medium",
            evidence=[f"Observed SQL port(s): {', '.join(map(str, sorted(mssql_ports)))}", *[t for t in sorted(data.technologies) if "SQL Server" in t]],
            commands=[f"netexec mssql {target_ip(data)} --port {port} -u '<authorized-user>' -p '<password>'" for port in sorted(mssql_ports)],
        ))

    winrm_ports = service_ports(data, "winrm")
    if winrm_ports:
        findings.append(Finding(
            "WinRM access prerequisite",
            "A WinRM-compatible endpoint needs authorized credentials and remote-management rights. NTLM metadata or an open port does not prove shell access.",
            "low",
            evidence=[f"Observed WinRM port(s): {', '.join(map(str, sorted(winrm_ports)))}"],
            commands=[f"evil-winrm -i {target_name(data)} -P {port}{' -S' if service_uses_tls(data, port) else ''} -u '<authorized-user>' -p '<password>'" for port in sorted(winrm_ports)],
        ))
    if service_ports(data, "rdp"):
        findings.append(Finding("RDP access prerequisite", "RDP requires authorized credentials, logon rights and compatible NLA/TLS policy; an open port is not a vulnerability.", "low",
                                evidence=[f"Observed RDP port(s): {', '.join(map(str, sorted(service_ports(data, 'rdp'))))}"],
                                commands=["Review the recorded RDP/NLA metadata before attempting an authorized interactive login."]))

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
            evidence=[f"Version: {data.ports[(22, 'tcp')].version or data.ports[(22, 'tcp')].service}"],
            commands=[
                f"netexec ssh {target_ip(data)} -u users.txt -p '<password>'",
                f"ssh <user>@{target_ip(data)}",
            ],
        ))

    if 53 in ports or (53, "udp") in data.ports:
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
            lines.append("### Evidence lineage and prerequisites")
            for match in data.vuln_matches[:40]:
                lines.append(f"- {md_code(match.vuln_id)} — {match.status}; target {md_code(public_target(match.target) or 'unattributed')}.")
                for evidence in match.evidence[:4]:
                    lines.append(f"  - Source: {md_code(evidence['path'] + ':' + str(evidence['line']))}; locator {md_code(evidence.get('locator', ''))}; SHA-256 {md_code(evidence['sha256'])}.")
                if match.prerequisites:
                    lines.append("  - Prerequisites: " + " ".join(match.prerequisites))
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

    if data.service_observations:
        lines.extend(["## Observed service access and metadata", "", "These records distinguish observed access, service fingerprints and conditional configuration leads. They are not automatically vulnerabilities.", "",
                      "| Service | Endpoint | Observation/status | Platform/domain | Evidence |", "|---|---|---|---|---|"])
        for observed in data.service_observations[:60]:
            evidence = observed.evidence[0]
            fact = " ".join(value for value in (observed.kind, observed.status, observed.resource, observed.access, observed.product, observed.version) if value)
            context = " / ".join(value for value in (observed.platform, observed.domain, observed.hostname) if value)
            lines.append("| " + " | ".join(md_escape_table(value) for value in (observed.service, public_target(observed.target), fact, context, f"{evidence['path']}:{evidence['line']}")) + " |")
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


def public_target(target: str) -> str:
    """Overview URLs retain input names, never credentials or query values."""
    try:
        value = urllib.parse.urlsplit(target)
        if not value.scheme or not value.hostname:
            return target[:180]
        host = f"[{value.hostname}]" if ":" in value.hostname else value.hostname
        if value.port:
            host += f":{value.port}"
        names = list(dict.fromkeys(name for name, _ in urllib.parse.parse_qsl(value.query, keep_blank_values=True)))
        query = "&".join(urllib.parse.quote(name[:80], safe="") for name in names[:20])
        return urllib.parse.urlunsplit((value.scheme, host, value.path, query, ""))
    except ValueError:
        return "<invalid target>"


def route_eligible(data: ReconData, match: VulnMatch) -> bool:
    if not match.evidence or not match.target or not in_scope(data, match.target):
        return False
    if match.status == "scanner-match":
        return severity_rank(match.severity) < 4 or (match.source == "NMAP-NSE" and match.severity == "unknown")
    if match.source == "SERVICE-EVIDENCE":
        return match.status in {"access-observed", "conditional-lead"}
    if match.source == "OSV":
        key = f"{match.ecosystem}:{match.package}"
        return any(row["kind"] == "observed" and row["version"] == match.version and row["target"] == match.target for row in data.package_evidence.get(key, []))
    return match.source == "LOCAL-RULE" and match.confidence == "high" and bool(match.version and match.version != "version unknown")


def service_access_leads(data: ReconData) -> list[VulnMatch]:
    leads = []
    for observed in data.service_observations:
        title, prerequisite, next_test, status = "", "", "", "access-observed"
        if observed.kind == "anonymous-share-access" and observed.status == "access-observed":
            title = "Anonymous/guest-readable SMB shares"
            prerequisite = "Access was observed with empty credentials; verify whether the exposed content is intended to be public."
            next_test = f"List share {observed.resource} with the same empty-credential session; inspect a small allowed sample for exposed configuration."
        elif observed.kind == "anonymous-objects" and observed.status == "access-observed":
            title = "Anonymous LDAP object access"
            prerequisite = "Anonymous object attributes were returned; determine whether this directory exposure is intended."
            context = f" for {observed.domain}" if observed.domain else ""
            next_test = f"Repeat a bounded anonymous query{context}; review returned object types and intended access policy."
        elif observed.kind == "signing-not-required":
            title, status = "SMB signing is not required: conditional relay lead", "conditional-lead"
            prerequisite = "Needs controlled authentication (credentials/authorized coercion), a reachable compatible relay path and target rights. None are established."
            next_test = "Verify signing policy and relay prerequisites on this host; do not infer a working relay path from negotiation alone."
        if not title:
            continue
        leads.append(score_vuln_match(data, VulnMatch("SERVICE-EVIDENCE", observed.kind, title=title,
            severity="low" if status == "conditional-lead" else "medium", confidence="low" if status == "conditional-lead" else "medium",
            target=observed.target, evidence=observed.evidence, status=status,
            prerequisites=[prerequisite], next_test=next_test,
            context={"platform": observed.platform, "domain": observed.domain, "hostname": observed.hostname,
                     "service": observed.service, "access": observed.access, "resource": observed.resource})))
    return leads


def build_overview(data: ReconData) -> dict:
    routes, grouped = [], {}
    candidates = top_vuln_candidates(data, limit=len(data.vuln_matches)) + service_access_leads(data)
    for match in sorted(candidates, key=lambda match: (-match.relevance, severity_rank(match.severity), match.vuln_id)):
        if not route_eligible(data, match):
            continue
        advisory_ids = sorted(set(value for value in [match.vuln_id, *match.aliases] if re.fullmatch(r"(?:CVE-\d{4}-\d+|GHSA-[a-z0-9-]+)", value, re.I)))
        target = public_target(match.target)
        parsed = urllib.parse.urlsplit(target)
        origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else target
        key = (origin, tuple(advisory_ids) or match.vuln_id)
        affected_input = {"target": target, "method": match.request_method or None,
                          "parameter": match.parameter or None, "position": match.parameter_position or None,
                          "session_present": match.session_present, "evidence": match.evidence}
        if match.context:
            affected_input["context"] = match.context
        if key in grouped:
            route = grouped[key]
            if affected_input not in route["inputs"]:
                route["inputs"].append(affected_input)
            route["evidence"].extend(row for row in match.evidence if row not in route["evidence"])
            continue
        if len(routes) == 3:
            continue
        route_id = hashlib.sha256(repr(key).encode()).hexdigest()[:12]
        route = {
            "id": route_id, "title": first_text(match.title or match.vuln_id, 110),
            "target": target, "severity": match.severity,
            "confidence": match.confidence, "status": match.status, "source": match.source,
            "template_id": match.vuln_id if match.source == "NUCLEI" else None,
            "advisory_ids": advisory_ids, "evidence": list(match.evidence), "inputs": [affected_input],
            "prerequisites": match.prerequisites or ["Confirm deployment and affected feature; prerequisites are not yet established."],
            "next_test": match.next_test,
        }
        if match.context:
            route["context"] = match.context
        routes.append(route)
        grouped[key] = route
    coverage = list(dict.fromkeys(data.coverage + data.vuln_errors))
    return {"schema_version": 1, "status": "partial" if coverage else "complete",
            "targets": sorted({public_target(v) for v in data.web_urls if in_scope(data, v)} | {v for v in (data.ip, data.host) if v}),
            "assessment_run": data.latest_assessment or None, "coverage": coverage,
            "limitations": list(dict.fromkeys(["Scanner hits require manual confirmation. Authentication, authorization and business logic require separate review."] + data.assessment_limits)),
            "routes": routes}


def render_overview(overview: dict) -> str:
    lines = ["# Recon overview", "", f"Coverage: **{overview['status']}**. Ranked by observed evidence before advisory severity.", ""]
    if not overview["routes"]:
        lines += ["No actionable attack route is established by the current evidence. This does not mean the target is secure.", ""]
    for index, route in enumerate(overview["routes"], 1):
        evidence = route["evidence"][0]
        path = evidence["path"].replace("\\", "/")
        label = f"{Path(path).name}:{evidence['line']}"
        title = route["title"].replace("\n", " ")
        others = f" +{len(route['inputs']) - 1} other inputs" if len(route["inputs"]) > 1 else ""
        lines += [f"{index}. **{title}** — `{route['target']}`{others} ({route['status']}, {route['confidence']} confidence).",
                  f"   Evidence: [{label}](<{urllib.parse.quote(path, safe='/._-')}>). " + (", ".join(route["advisory_ids"]) + "." if route["advisory_ids"] else ""),
                  "   Prerequisite: " + first_text(" ".join(route["prerequisites"]), 160),
                  "   Next test: " + first_text(route["next_test"], 170), ""]
    notes = overview["coverage"][:3]
    if notes:
        lines += ["Coverage gaps: " + " ".join(first_text(note, 120) for note in notes), ""]
    lines += [overview["limitations"][0], "", "Full evidence and remaining coverage notes: `overview.json` and `recon-analysis.md`.", ""]
    return "\n".join(lines)


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
        overview = build_overview(data)
        (out_path.parent / "overview.json").write_text(json.dumps(overview, indent=2) + "\n", encoding="utf-8")
        (out_path.parent / "overview.md").write_text(render_overview(overview), encoding="utf-8")

        print(f"[+] Recon root: {root}")
        print(f"[+] Parsed files: {len(data.files)}")
        print(f"[+] Open ports parsed: {len(data.ports)}")
        print(f"[+] Findings generated: {len(findings)}")
        print(f"[+] Packages/components detected: {len(data.package_versions)}")
        print(f"[+] Vulnerability matches: {len(data.vuln_matches)}")
        print(f"[+] Wrote analysis: {out_path}")
        print(f"[+] Wrote overview: {out_path.parent / 'overview.md'}")

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
