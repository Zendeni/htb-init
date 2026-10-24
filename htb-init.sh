#!/usr/bin/env bash

set -euo pipefail

INITIALIZER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INIT_SOURCE_DIR="$INITIALIZER_DIR"

usage() {
    cat <<'USAGE'
Usage:
  htb-init.sh <box-name> <target-ip>
  htb-init.sh --prepare <existing-workspace>
  htb-init.sh --inspect <workspace> [--json]
  htb-init.sh --review <workspace> [ScopeLens review options]
  htb-init.sh --doctor
  htb-init.sh --rules

Workspaces: $HOME/htb_labs by default; override with HTB_LABS_ROOT.
Offline review commands require ScopeLens 0.2+ in the selected Python.
Override the Python executable with HTB_PYTHON (default: python3).
USAGE
}

# Offline integration stays in this entrypoint so copied installations keep
# working. All commands use the same interpreter, isolated from workspace code.
REVIEW_PYTHON="${HTB_PYTHON:-python3}"

scopelens_available() {
    command -v "$REVIEW_PYTHON" >/dev/null 2>&1 &&
        "$REVIEW_PYTHON" -I -c 'import scopelens.workspace' >/dev/null 2>&1
}

scopelens_setup_hint() {
    echo "    Activate the environment where ScopeLens is installed, or set HTB_PYTHON."
    echo "    Setup: https://github.com/Zendeni/scopelens#try-it"
}

dispatch_offline() {
    local command="$1"
    shift
    if ! scopelens_available; then
        echo "[-] Offline review requires ScopeLens 0.2+ in $REVIEW_PYTHON." >&2
        scopelens_setup_hint >&2
        return 2
    fi
    # exec preserves ScopeLens exit codes, including review thresholds and
    # interruptions. Pass arguments as separate values, without shell parsing.
    exec "$REVIEW_PYTHON" -I -m scopelens "$command" "$@"
}

prepare_offline_review() {
    local workspace="$1" name="$2"
    if ! scopelens_available; then
        echo "[i] Install ScopeLens 0.2+ to add offline analysis and inspection:"
        scopelens_setup_hint
        printf '    Then run: scopelens prepare %q\n' "$workspace"
        return 0
    fi
    if "$REVIEW_PYTHON" -I -m scopelens prepare "$workspace" --name "$name"; then
        echo "[+] Offline review: ./inspect.sh, then ./analyze.sh"
        echo "[+] Compare a later snapshot: ./analyze.sh --baseline latest"
    else
        echo "[!] Workspace created; offline review setup needs attention." >&2
        printf '    Run: scopelens prepare %q\n' "$workspace" >&2
    fi
}

case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
    --prepare|--inspect|--review|--doctor|--rules)
        REVIEW_COMMAND="${1#--}"
        shift
        dispatch_offline "$REVIEW_COMMAND" "$@"
        exit $?
        ;;
    --*)
        printf '[-] Unknown option: %s\n' "$1" >&2
        usage >&2
        exit 2
        ;;
esac

if [ "$#" -ne 2 ]; then
    usage >&2
    exit 2
fi

BOX="$1"
IP="$2"

if [[ ! "$BOX" =~ ^[A-Za-z0-9._-]+$ ]] || [[ "$BOX" == "." || "$BOX" == ".." ]]; then
    echo "[-] Invalid box name. Use letters, numbers, dot, underscore, or dash."
    exit 1
fi

if [[ "$BOX" == *.htb ]]; then
    echo "[-] Use the short box name only, e.g. 'principal', not 'principal.htb'."
    exit 1
fi

if [[ ! "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "[-] Invalid IPv4 address format."
    exit 1
fi

IFS='.' read -r o1 o2 o3 o4 <<< "$IP"
for octet in "$o1" "$o2" "$o3" "$o4"; do
    if (( 10#$octet > 255 )); then
        echo "[-] Invalid IPv4 address octet: $octet"
        exit 1
    fi
done

printf -v IP '%d.%d.%d.%d' "$((10#$o1))" "$((10#$o2))" "$((10#$o3))" "$((10#$o4))"

HOST="${BOX}.htb"
BASE_ROOT="${HTB_LABS_ROOT:-${HOME:?HOME must be set}/htb_labs}"
BASE_DIR="$BASE_ROOT/$BOX"

if [[ -L "$BASE_DIR" || -L "$BASE_DIR/.target.env" ]]; then
    echo "[-] Refusing a linked workspace or target configuration: $BASE_DIR" >&2
    exit 2
fi
if [[ -e "$BASE_DIR/.recon.lock" ]]; then
    echo "[-] Refusing to reinitialize a workspace while its recon lock exists: $BASE_DIR" >&2
    exit 2
fi

echo "[+] Creating HTB workspace for $BOX"
echo "[+] Target IP: $IP"
echo "[+] Hostname: $HOST"
echo "[+] Workspace: $BASE_DIR"

mkdir -p "$BASE_DIR"/{scans,enum/{web,dns,smb,ftp,nfs,snmp,ldap,kerberos,rpc,winrm,rdp,mssql,ssh,windows,ad,mqtt,other},loot/{copied,searches},exploits,shells,screenshots,tools}
cd "$BASE_DIR"
BASE_DIR="$PWD"

if [ -f "$INIT_SOURCE_DIR/analyze-recon.py" ] && [ ! -L "$INIT_SOURCE_DIR/analyze-recon.py" ]; then
    cp -- "$INIT_SOURCE_DIR/analyze-recon.py" tools/analyze-recon.py
    chmod +x tools/analyze-recon.py
fi

cat > .target.env <<EOF
BOX="$BOX"
IP="$IP"
HOST="$HOST"
# Extra vhost base domains discovered from redirects are stored during recon in:
#   enum/dns/vhost-base-domains.txt
EOF
printf 'BASE_DIR=%q\n' "$BASE_DIR" >> .target.env

# Keep the assessor alongside its workspace so it remains usable independently
# of this checkout. A copied initializer still works without the optional asset.
if [[ -f "$INITIALIZER_DIR/web-assess.py" ]]; then
    if [[ "$INITIALIZER_DIR" != "$BASE_DIR" ]]; then
        cp "$INITIALIZER_DIR/web-assess.py" ./web-assess.py
    fi
    cat > web-assess.sh <<'WEB_ASSESS_EOF'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${HTB_PYTHON:-python3}" -I "$SCRIPT_DIR/web-assess.py" --workspace "$SCRIPT_DIR" "$@"
WEB_ASSESS_EOF
    chmod +x web-assess.sh
else
    echo "[i] web-assess.py is not alongside the initializer; automatic web assessment unavailable."
    echo "    Use the full repository checkout to install the web assessment helper."
fi

cat > update-hosts.sh <<'EOF'
#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source ./.target.env

tmpfile="$(mktemp)"
hostsfile="$(mktemp)"
trap 'rm -f "$tmpfile" "$hostsfile"' EXIT

echo "[+] Updating /etc/hosts for $HOST"

# Always include the primary HTB hostname. If recon has already discovered
# redirect/vhost names such as watcher.vl or zabbix.watcher.vl, include those too.
{
    echo "$HOST"
    cat enum/dns/vhost-base-domains.txt 2>/dev/null || true
    cat enum/dns/discovered-hostnames.txt 2>/dev/null || true
    awk '{for (i=2; i<=NF; i++) print $i}' enum/dns/hosts-additions.txt 2>/dev/null || true
    awk '{for (i=2; i<=NF; i++) print $i}' enum/ad/hosts-additions.txt 2>/dev/null || true
} | sed '/^[[:space:]]*$/d' \
    | tr '[:upper:]' '[:lower:]' \
    | awk '$0 !~ /^(fuzz|hostmaster|domaindnszones|forestdnszones)\./ && $0 !~ /_msdcs/' \
    | sort -u > "$hostsfile"

echo "[+] Hostnames to map:"
sed 's/^/    - /' "$hostsfile"

awk -v hosts_file="$hostsfile" '
BEGIN {
    while ((getline h < hosts_file) > 0) { remove[h] = 1 }
}
{
    keep = 1
    for (i = 2; i <= NF; i++) {
        if ($i in remove) keep = 0
    }
    if (keep) print
}
' /etc/hosts > "$tmpfile"

if [ -s "$hostsfile" ]; then
    printf "%s " "$IP" >> "$tmpfile"
    tr '\n' ' ' < "$hostsfile" >> "$tmpfile"
    printf "\n" >> "$tmpfile"
fi

sudo cp "$tmpfile" /etc/hosts

echo "[+] Current hosts entries:"
while read -r name; do
    [ -n "$name" ] && getent hosts "$name" || true
done < "$hostsfile"
EOF

chmod +x update-hosts.sh

if [ ! -f notes.md ]; then
cat > notes.md <<EOF
# $BOX Notes

## Target

- IP: $IP
- Hostname: $HOST
- Platform: Unknown
- Difficulty: Unknown

## Open Ports

| Port | Service | Version | Notes |
|---:|---|---|---|
| | | | |

## Credentials

| Username | Password | Source |
|---|---|---|
| | | |

## Interesting Findings

-

## Attack Ideas

-

## Foothold

-

## Privilege Escalation

-

## Loot

-

## User Proof

-

## Root Proof

-
EOF
else
    echo "[+] Existing notes.md found; leaving it unchanged."
fi

if [ ! -f writeup.md ]; then
cat > writeup.md <<EOF
# Hack The Box - $BOX

## Executive Summary

The target machine \$BOX was assessed as part of an authorized Hack The Box lab.

## Target Information

| Item | Value |
|---|---|
| Machine | $BOX |
| Target IP | $IP |
| Hostname | $HOST |
| Platform | TBD |
| Difficulty | TBD |
| Assessment Type | Authorized HTB Lab |

---

# 1. Enumeration

## 1.1 TCP Port Discovery

\`\`\`bash
nmap -p- --min-rate 5000 -Pn $IP -oN scans/tcp-full.txt
\`\`\`

## 1.2 Service and Version Enumeration

\`\`\`bash
nmap -sC -sV -Pn -p <ports> $IP -oN scans/tcp-services.txt
\`\`\`

## 1.3 Web Enumeration

\`\`\`bash
cat enum/web/live-web-urls.txt
whatweb <url>
feroxbuster -u <url> -w <web-wordlist> -x php,txt,html,js,bak,old,zip,tar,gz,conf,config,json,yml,xml,log -k
ffuf -ac -w <dns-wordlist> -u <url>/ -H "Host: FUZZ.$HOST"
\`\`\`

## 1.4 Service Summary

| Port | Service | Version | Notes |
|---:|---|---|---|
| | | | |

---

# 2. Initial Access

## Vulnerability Identification

| Finding | Description |
|---|---|
| Vulnerability | TBD |
| Affected Service | TBD |
| Impact | Initial access |
| Authentication Required | TBD |

## Exploitation

\`\`\`bash
PASTE_EXPLOIT_COMMANDS_HERE
\`\`\`

## Shell Stabilization

\`\`\`bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
stty rows 40 columns 120
\`\`\`

---

# 3. Local Enumeration

\`\`\`bash
whoami
id
hostname
uname -a
cat /etc/os-release
sudo -l
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
ps aux
ss -tulpn
cat /etc/crontab
\`\`\`

---

# 4. Privilege Escalation

## Privilege Escalation Vector

| Vector | Details |
|---|---|
| Technique | TBD |
| Weakness | TBD |
| Abused Component | TBD |
| Result | Root shell |

## Exploitation

\`\`\`bash
PASTE_PRIVESC_COMMANDS_HERE
\`\`\`

---

# 5. Attack Chain Summary

\`\`\`text
1. Performed full TCP port discovery.
2. Enumerated discovered services.
3. Identified exposed attack surface.
4. Discovered initial access vector.
5. Exploited the weakness to obtain a low-privileged shell.
6. Performed local enumeration.
7. Identified privilege escalation path.
8. Abused local misconfiguration/vulnerability to obtain root access.
\`\`\`

## MITRE ATT&CK Mapping

| Phase | Technique | ID |
|---|---|---|
| Reconnaissance | Active Scanning | T1595 |
| Initial Access | Exploit Public-Facing Application | T1190 |
| Execution | Command and Scripting Interpreter | T1059 |
| Discovery | System Information Discovery | T1082 |
| Discovery | System Owner/User Discovery | T1033 |
| Privilege Escalation | Abuse Elevation Control Mechanism | T1548 |

---

# 6. Remediation Summary

- Patch the vulnerable service or application.
- Disable unnecessary exposed services.
- Remove sensitive files from exposed paths.
- Rotate compromised credentials.
- Enforce least privilege.
- Harden file permissions.
- Review sudo rules, SUID binaries, scheduled tasks, and writable paths.
- Improve logging and alerting.
EOF
else
    echo "[+] Existing writeup.md found; leaving it unchanged."
fi

cat > zip-recon.sh <<'EOF'
#!/usr/bin/env bash

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BOX="$(basename "$PWD")"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
OUTFILE="${BOX}-recon-${TIMESTAMP}.zip"

if ! command -v zip >/dev/null 2>&1; then
    echo "[-] zip not found; cannot create archive."
    exit 1
fi

echo "[+] Creating recon archive: $OUTFILE"
echo "[!] Local archive includes raw requests and scanner evidence, which may contain session credentials."

REVIEW_FILES=()
for REVIEW_FILE in scope.json analyze.sh inspect.sh ANALYSIS.md recon-analysis.md overview.md overview.json run-status.json run-stages.tsv run-target.env tools/analyze-recon.py web-assess.sh web-assess.py; do
    if [[ -f "$REVIEW_FILE" && ! -L "$REVIEW_FILE" ]]; then
        REVIEW_FILES+=("$REVIEW_FILE")
    fi
done

zip -r "$OUTFILE" \
    .target.env \
    "${REVIEW_FILES[@]}" \
    scans/ \
    enum/ \
    notes.md \
    writeup.md \
    README.md \
    recon.sh \
    search-recon.sh \
    file-hunt.sh \
    update-hosts.sh \
    zip-recon.sh \
    privesc-linux.md \
    summary.md \
    recon-console.log \
    -x "*.git*" \
    -x "loot/*" \
    -x "exploits/*" \
    -x "shells/*" \
    -x "screenshots/*" \
    -x "*.pcap" \
    -x "*.cap" \
    -x "*.zip"

chmod 600 "$OUTFILE"
echo "[+] Recon archive created:"
ls -lh "$OUTFILE"
EOF

chmod +x zip-recon.sh

cat > search-recon.sh <<'EOF'
#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "Usage: ./search-recon.sh <regex-or-string> [--copy]"
    echo "Example: ./search-recon.sh 'password|token|backup' --copy"
    exit 1
fi

PATTERN="$1"
COPY_MATCHES="${2:-}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
OUTFILE="loot/searches/recon-search-${TIMESTAMP}.txt"

mkdir -p loot/searches loot/copied

echo "[+] Searching recon output for: $PATTERN"
echo "[+] Writing matches to: $OUTFILE"

if command -v rg >/dev/null 2>&1; then
    rg -n --hidden --glob '!*.zip' --glob '!loot/copied/**' --glob '!recon-console.log' "$PATTERN" scans enum notes.md writeup.md summary.md recon-analysis.md 2>/dev/null \
        | tee "$OUTFILE" || true
else
    grep -RniI \
        --exclude="*.zip" \
        --exclude="recon-console.log" \
        --exclude-dir="loot/copied" \
        -E "$PATTERN" scans enum notes.md writeup.md summary.md recon-analysis.md 2>/dev/null \
        | tee "$OUTFILE" || true
fi

if [ "$COPY_MATCHES" = "--copy" ]; then
    echo "[+] Copying matched local files into loot/copied/"

    cut -d: -f1 "$OUTFILE" \
        | sort -u \
        | while read -r FILE; do
            [ -f "$FILE" ] || continue
            REL="${FILE#./}"
            DEST="loot/copied/$REL"
            mkdir -p "$(dirname "$DEST")"
            cp "$FILE" "$DEST"
        done
fi

echo "[+] Done."
EOF

chmod +x search-recon.sh

cat > file-hunt.sh <<'EOF'
#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "Usage: ./file-hunt.sh <filename-pattern> [root]"
    echo "Example: ./file-hunt.sh 'config.php' /"
    echo "Example: ./file-hunt.sh '*.bak' /var/www"
    exit 1
fi

PATTERN="$1"
ROOT="${2:-.}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
OUTFILE="loot/searches/file-hunt-${TIMESTAMP}.txt"
COPY_ROOT="loot/copied/file-hunt-${TIMESTAMP}"

mkdir -p loot/searches "$COPY_ROOT"

echo "[+] Finding readable files matching: *$PATTERN*"
echo "[+] Root: $ROOT"
echo "[+] Writing file list to: $OUTFILE"

find "$ROOT" -type f -iname "*$PATTERN*" -readable -size -20M -print 2>/dev/null \
    | tee "$OUTFILE" || true

echo "[+] Copying readable matches under: $COPY_ROOT"

while read -r FILE; do
    [ -f "$FILE" ] || continue
    REL="${FILE#/}"
    DEST="$COPY_ROOT/$REL"
    mkdir -p "$(dirname "$DEST")"
    cp "$FILE" "$DEST" 2>/dev/null || true
done < "$OUTFILE"

echo "[+] Done. Review:"
echo "    $OUTFILE"
echo "    $COPY_ROOT"
EOF

chmod +x file-hunt.sh

cat > recon.sh <<'EOF'
#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source ./.target.env

START_TIME="$(date)"
START_EPOCH="$(date +%s)"
TOTAL_STAGES=24

# Runtime safety knobs. Defaults are intentionally conservative so recon does not
# appear to hang in ffuf/ferox sections on dynamic or slow web targets.
# Override per run, for example:
#   ./recon.sh
#   WEB_ENUM=0 ./recon.sh
#   FEROX_EXTENSIONS=0 FEROX_COLLECT=0 ./recon.sh
#   RECON_DEEP=1 FEROX_EXTENSIONS=1 FEROX_COLLECT=1 FFUF_CONTENT=1 ./recon.sh
#   ONLINE_VULN_CHECK=0 ./recon.sh
RECON_DEEP="${RECON_DEEP:-0}"
WEB_ENUM="${WEB_ENUM:-1}"
WEB_ASSESS="${WEB_ASSESS:-${NUCLEI_ENABLE:-$RECON_DEEP}}"
RECON_PYTHON="${HTB_PYTHON:-python3}"
WEB_SESSION_FILE="${WEB_SESSION_FILE:-}"
WEB_REQUESTS_FILE="${WEB_REQUESTS_FILE:-}"
WEB_ASSESS_ARGS_FILE="${WEB_ASSESS_ARGS_FILE:-}"
MAX_JS_FILES="${MAX_JS_FILES:-40}"
FEROX_ENABLE="${FEROX_ENABLE:-1}"
FEROX_EXTENSIONS="${FEROX_EXTENSIONS:-0}"
FEROX_COLLECT="${FEROX_COLLECT:-0}"
FFUF_CONTENT="${FFUF_CONTENT:-0}"
FFUF_VHOST="${FFUF_VHOST:-1}"
FFUF_THREADS="${FFUF_THREADS:-15}"
FFUF_RATE="${FFUF_RATE:-50}"
FFUF_MAXTIME="${FFUF_MAXTIME:-180}"
FEROX_MAXTIME="${FEROX_MAXTIME:-240}"
FEROX_THREADS="${FEROX_THREADS:-10}"
NIKTO_MAXTIME="${NIKTO_MAXTIME:-600}"
NIKTO_ENABLE="${NIKTO_ENABLE:-$RECON_DEEP}"
NUCLEI_MAXTIME="${NUCLEI_MAXTIME:-600}"
NUCLEI_ENABLE="${NUCLEI_ENABLE:-$WEB_ASSESS}"
WEB_ASSESS_MAXTIME="${WEB_ASSESS_MAXTIME:-2100}"
SCANNER_UPDATE_MAXTIME="${SCANNER_UPDATE_MAXTIME:-180}"
UPDATE_SCANNER_DATA="${UPDATE_SCANNER_DATA:-1}"
NMAP_MAXTIME="${NMAP_MAXTIME:-900}"
SERVICE_ENUM_MAXTIME="${SERVICE_ENUM_MAXTIME:-300}"
WEB_PROBE_MAXTIME="${WEB_PROBE_MAXTIME:-120}"
CURL_MAXTIME="${CURL_MAXTIME:-20}"
ANALYZER_MAXTIME="${ANALYZER_MAXTIME:-900}"
ARCHIVE_MAXTIME="${ARCHIVE_MAXTIME:-300}"
VULN_SCAN="${VULN_SCAN:-$RECON_DEEP}"
MQTT_ENUM_MAXTIME="${MQTT_ENUM_MAXTIME:-30}"
MQTT_ALL_TOPICS="${MQTT_ALL_TOPICS:-$RECON_DEEP}"
MAX_WEB_URLS="${MAX_WEB_URLS:-4}"
MAX_WEB_WORDLISTS="${MAX_WEB_WORDLISTS:-1}"
MAX_FFUF_WORDLISTS="${MAX_FFUF_WORDLISTS:-1}"
VHOST_SUFFIXES="${VHOST_SUFFIXES:-htb,vl,local}"
ONLINE_VULN_CHECK="${ONLINE_VULN_CHECK:-1}"
VULN_ANALYZER="${VULN_ANALYZER:-}"
VULN_TIMEOUT="${VULN_TIMEOUT:-20}"
MAX_VULN_RESULTS="${MAX_VULN_RESULTS:-8}"
KERBEROS_USERDB="${KERBEROS_USERDB:-}"
KERBEROS_REALM="${KERBEROS_REALM:-}"
TARGET_IS_WINDOWS=0
TARGET_IS_AD=0
AD_DOMAIN=""
AD_DC_HOST=""
WEB_ASSESS_RAN=0
# Deduplicate successful scans within this run only. Persisted .done files used
# to suppress later recon runs, even after a timeout or failed ffuf invocation.
declare -A VHOST_SCANS_DONE=()
CURRENT_STAGE=0
RUN_READY=0

record_result() {
    # One append also works from pipeline/command-substitution subshells. Never
    # log full argv: session headers and captured request paths can be private.
    printf '%s\t%s\t%s\t%s\n' "$CURRENT_STAGE" "$1" "$2" "${3//$'\t'/ }" >> run-stages.tsv
}

write_run_status() {
    "$RECON_PYTHON" -I - "$1" <<'STATUSPY'
import json
from pathlib import Path
import sys
path = Path('run-status.json')
report = json.loads(path.read_text(encoding='utf-8'))
stages = {}
for line in Path('run-stages.tsv').read_text(encoding='utf-8').splitlines():
    number, status, code, detail = line.split('\t', 3)
    stage = stages.setdefault(number, {'stage': int(number), 'name': detail, 'status': 'completed', 'commands': []})
    if status == 'started':
        stage['name'] = detail
        continue
    stage['commands'].append({'command': detail, 'status': status, 'returncode': int(code)})
for stage in stages.values():
    commands = stage['commands']
    if any(item['status'] == 'error' for item in commands):
        stage['status'] = 'error'
    elif commands and all(item['status'] == 'skipped' for item in commands):
        stage['status'] = 'skipped'
        stage['reason'] = '; '.join(item['command'] for item in commands)
report['stages'] = list(stages.values())
report['status'] = 'incomplete' if any(s['status'] == 'error' for s in report['stages']) else sys.argv[1]
temporary = path.with_suffix('.json.tmp')
temporary.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
temporary.replace(path)
STATUSPY
}

finish_run() {
    local status=$?
    trap - EXIT
    if [[ "$RUN_READY" == "1" ]]; then
        if [[ "$status" != "0" ]]; then
            record_result error "$status" "collector interrupted or aborted"
        fi
        write_run_status completed || status=2
        if grep -q $'\terror\t' run-stages.tsv; then status=2; fi
    fi
    rmdir .recon.lock 2>/dev/null || true
    exit "$status"
}

have() {
    command -v "$1" >/dev/null 2>&1
}

format_elapsed() {
    local elapsed="$1"
    printf '%02d:%02d:%02d' "$((elapsed / 3600))" "$(((elapsed % 3600) / 60))" "$((elapsed % 60))"
}

show_progress() {
    local current="$1"
    local label="$2"
    local now elapsed completed percent
    CURRENT_STAGE="$current"
    record_result started 0 "$label"

    now="$(date +%s)"
    elapsed="$((now - START_EPOCH))"
    completed="$((current - 1))"
    [ "$completed" -ge 0 ] || completed=0
    percent="$((completed * 100 / TOTAL_STAGES))"
    printf '[+] Progress: %3d%% | elapsed %s | stage %d/%d: %s\n' \
        "$percent" "$(format_elapsed "$elapsed")" "$current" "$TOTAL_STAGES" "$label"
}

find_vuln_analyzer() {
    local candidate

    for candidate in \
        "$VULN_ANALYZER" \
        "$SCRIPT_DIR/tools/analyze-recon.py" \
        "/home/zendeni/tools/htb/analyze-recon.py"; do
        if [ -n "$candidate" ] && [ -f "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    if have analyze-recon.py; then
        command -v analyze-recon.py
        return 0
    fi

    return 1
}

run_online_vuln_analysis() {
    local analyzer
    local -a analyzer_args=()

    analyzer="$(find_vuln_analyzer || true)"
    if [ -z "$analyzer" ]; then
        echo "[!] Analysis unavailable: analyze-recon.py was not found."
        echo "[!] Set VULN_ANALYZER=/path/to/analyze-recon.py and rerun recon."
        record_result error 127 "analyzer missing"
        return 0
    fi

    if [[ "$ONLINE_VULN_CHECK" == "1" ]]; then analyzer_args+=(--online-vuln-check); fi
    echo "[+] Analyzing collected evidence (online enrichment: $ONLINE_VULN_CHECK)"
    run_with_timeout "$ANALYZER_MAXTIME" "$RECON_PYTHON" -I "$analyzer" "$SCRIPT_DIR" \
        "${analyzer_args[@]}" \
        --vuln-timeout "$VULN_TIMEOUT" \
        --max-vuln-results "$MAX_VULN_RESULTS" || true
}

ports_lines() {
    echo "$PORTS" | tr ',' '\n'
}

service_ports() {
    # A confirmed service on an unusual port is as useful as a conventional
    # port. Discovery still supplies defaults when version detection failed.
    local defaults="$1" services="$2" description="${3:-}"
    awk -v defaults="$defaults" -v services="$services" -v description="$description" '
        $1 ~ /^[0-9]+\/tcp$/ && $2 == "open" {
            port=$1; sub(/\/tcp$/, "", port)
            if (port ~ defaults || tolower($3) ~ services ||
                (description != "" && tolower($0) ~ description)) print port
        }' scans/tcp-full.txt scans/tcp-services.txt | sort -nu | paste -sd, -
}

service_uses_tls() {
    case "$1" in 636|3269|5986) return 0 ;; esac
    awk -v port="$1/tcp" '$1 == port && $2 == "open" && $3 ~ /^(ssl\/|ldaps|https)/ { found=1 } END { exit !found }' scans/tcp-services.txt
}

url_in_scope() {
    "$RECON_PYTHON" -I - "$1" "$IP" "$HOST" <<'URLSCOPE'
import ipaddress
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit
try:
    value = sys.argv[1]
    if any(ord(c) <= 32 or ord(c) == 127 for c in value) or '\\' in value: raise ValueError('invalid URL')
    url = urlsplit(value)
    if url.scheme not in ('http', 'https') or not url.hostname or url.username is not None or url.password is not None: raise ValueError('invalid URL')
    port = url.port
    host = url.hostname.lower().rstrip('.')
    scope = {'include': sys.argv[2:], 'exclude': []}
    if Path('scope.json').exists(): scope = json.loads(Path('scope.json').read_text(encoding='utf-8'))
    def match(entry):
        if '/' in entry:
            try: return ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False)
            except ValueError: return False
        return host == entry.lower().rstrip('.')
    allowed = any(match(x) for x in scope['include']) and not any(match(x) for x in scope.get('exclude', []))
    raise SystemExit(0 if allowed else 1)
except (ValueError, TypeError, KeyError, OSError):
    raise SystemExit(1)
URLSCOPE
}

url_port() {
    local url="$1"
    local scheme remainder hostport

    scheme="${url%%://*}"
    remainder="${url#*://}"
    hostport="${remainder%%/*}"

    if [[ "$hostport" =~ :([0-9]+)$ ]]; then
        echo "${BASH_REMATCH[1]}"
    elif [ "$scheme" = "https" ]; then
        echo "443"
    else
        echo "80"
    fi
}

url_scheme() {
    echo "${1%%://*}"
}

url_host() {
    local url="$1"
    local remainder hostport

    remainder="${url#*://}"
    hostport="${remainder%%/*}"
    echo "${hostport%%:*}"
}

is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

is_hostname_candidate() {
    local name="$1"

    [ -n "$name" ] || return 1
    is_ipv4 "$name" && return 1
    [[ "$name" == *.* ]] || return 1
    [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || return 1
    return 0
}

is_web_hostname_candidate() {
    local name="${1,,}"

    is_hostname_candidate "$name" || return 1
    [[ "$name" != *_* ]] || return 1
    case "$name" in
        domaindnszones.*|forestdnszones.*|*._msdcs.*)
            return 1
            ;;
    esac
    return 0
}

is_web_candidate_port() {
    local port="$1" service_line service_name

    service_line="$(awk -v wanted="$port/tcp" '$1 == wanted && $2 == "open" {print; exit}' scans/tcp-services.txt 2>/dev/null)"
    service_name="$(printf '%s\n' "$service_line" | awk '{print tolower($3)}')"
    if [[ "$service_name" =~ ^(winrm|wsman|ssl/winrm|ssl/wsman)$ ]] || \
       { [[ "$port" =~ ^(5985|5986)$ ]] && printf '%s\n' "$service_line" | grep -Eiq 'microsoft[ -]httpapi'; }; then
        return 1
    fi
    if [[ "$service_name" =~ ^(http|https|ssl/http|http-alt|http-proxy)$ ]]; then
        return 0
    fi

    case "$port" in
        21|22|25|53|88|110|111|135|139|143|389|445|464|593|636|993|995|1433|1883|2179|3268|3269|3389|5985|5986|9389)
            return 1
            ;;
    esac

    if printf '%s\n' "$service_line" | grep -Eiq \
        'mqtt|msrpc|ncacn_http|vmrdp|ldap|kerberos|kpasswd|microsoft-ds|netbios|mc-nmf|message framing|rpc over http'; then
        return 1
    fi
    return 0
}

is_vhost_base_candidate() {
    local name="$1"
    local suffix
    local -a allowed_suffixes

    [ "$name" = "${HOST,,}" ] && return 0

    IFS=',' read -r -a allowed_suffixes <<< "$VHOST_SUFFIXES"
    for suffix in "${allowed_suffixes[@]}"; do
        suffix="${suffix//[[:space:]]/}"
        suffix="${suffix#.}"
        if [ -n "$suffix" ] && [[ "$name" == *."$suffix" ]]; then
            return 0
        fi
    done

    return 1
}

record_vhost_base_domain() {
    local name="$1"

    name="$(printf '%s' "$name" | sed 's/[[:space:]]//g; s/:$//; s/^\.//; s/\.$//' | tr '[:upper:]' '[:lower:]')"
    is_hostname_candidate "$name" || return 0
    is_vhost_base_candidate "$name" || return 0
    mkdir -p enum/dns
    append_unique_line "$name" enum/dns/vhost-base-domains.txt
}

collect_vhost_base_domains() {
    local url host location host_from_location

    mkdir -p enum/dns
    touch enum/dns/vhost-base-domains.txt
    record_vhost_base_domain "$HOST"

    # If the direct URL hostname is already a real hostname, include it.
    for url in "$@"; do
        [ -z "$url" ] && continue
        host="$(url_host "$url")"
        record_vhost_base_domain "$host"
    done

    # Critical HTB/VL case: port 80 often redirects from the IP to the real vhost
    # namespace, e.g. Location: http://watcher.vl/. Fuzz both FUZZ.$HOST and
    # FUZZ.<redirect-host>, otherwise subdomains like zabbix.watcher.vl are missed.
    { grep -RhoEi '^location:[[:space:]]*https?://[^/[:space:]]+' enum/web/headers-*.txt enum/web/*headers*.txt 2>/dev/null || true; } | while read -r location; do
        host_from_location="$(printf '%s' "$location" | sed -E 's/^location:[[:space:]]*https?:\/\///I; s#/.*##; s/:.*$//')"
        record_vhost_base_domain "$host_from_location"
    done

    { grep -RhoE 'https?://[A-Za-z0-9._-]+' enum/web enum/dns 2>/dev/null || true; } | while read -r location; do
        host_from_location="$(url_host "$location")"
        record_vhost_base_domain "$host_from_location"
    done
}

safe_name() {
    echo "$1" | sed 's#[/:?&=.]#_#g'
}

pick_first_file() {
    for candidate in "$@"; do
        if [ -f "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

truncate_lines() {
    local max_lines="${1:-500}"
    awk -v max_lines="$max_lines" '
        NR <= max_lines { print substr($0, 1, 300) }
        END { if (NR > max_lines) printf("[... truncated %d additional lines ...]\n", NR - max_lines) }
    '
}

run_with_timeout() {
    local seconds="$1"
    local status
    shift

    if ! have timeout; then
        echo "[-] timeout is required to run bounded commands safely." >&2
        return 127
    fi

    if timeout --signal=TERM --kill-after=10 "$seconds" "$@"; then
        record_result completed 0 "${1##*/}"
        return 0
    else
        status="$?"
    fi
    if [[ "${1##*/}" == bash && "${2:-}" == ./web-assess.sh && "$status" == 1 ]]; then
        record_result completed 1 "web-assess findings"
        return 1
    fi
    record_result error "$status" "${1##*/}"
    if [ "$status" -eq 124 ] || [ "$status" -eq 137 ]; then
        echo "[!] Command exceeded ${seconds}s and was terminated: $1" >&2
    else
        echo "[!] Command exited with status $status: $1" >&2
    fi
    return "$status"
}

run_bounded_listener() {
    local seconds="$1"
    local status
    shift

    if timeout --signal=TERM --kill-after=10 "$seconds" "$@"; then
        record_result completed 0 "${1##*/}"
        return 0
    else
        status="$?"
    fi
    if [[ "$status" == 124 || "$status" == 137 ]]; then
        record_result completed 0 "${1##*/} bounded collection window ended"
        return 0
    fi
    record_result error "$status" "${1##*/}"
    echo "[!] Bounded listener exited with status $status: $1" >&2
    return "$status"
}

run_fetch_curl() {
    local status
    if curl --noproxy '*' "$@"; then
        record_result completed 0 curl
        return 0
    else
        status=$?
        record_result error "$status" curl
        return "$status"
    fi
}

refresh_scanner_data() {
    if [ "$UPDATE_SCANNER_DATA" != "1" ]; then
        echo "[!] Skipping scanner-data refresh because UPDATE_SCANNER_DATA=$UPDATE_SCANNER_DATA."
        return 0
    fi

    if [[ "$NUCLEI_ENABLE" == "1" || "$WEB_ASSESS" == "1" ]] && have nuclei; then
        echo "[+] Updating Nuclei templates before scanning."
        run_with_timeout "$SCANNER_UPDATE_MAXTIME" nuclei -update-templates || true
    elif have nuclei; then
        echo "[i] Skipping Nuclei template refresh because Nuclei is disabled in standard mode."
    fi

    if have nmap; then
        echo "[+] Rebuilding Nmap's local NSE script database."
        run_with_timeout "$SCANNER_UPDATE_MAXTIME" nmap --script-updatedb || true
    fi

    if have nikto; then
        echo "[+] Nikto will perform its built-in update check when its scan starts."
    fi
}

append_unique_line() {
    local value="$1"
    local file="$2"

    [ -n "$value" ] || return 0
    touch "$file"
    grep -Fxq "$value" "$file" 2>/dev/null || echo "$value" >> "$file"
}

detect_target_profile() {
    local clock_skew short_dc

    mkdir -p enum/windows enum/ad
    : > enum/ad/hosts-additions.txt

    if grep -Eiq 'Microsoft Windows|OS: Windows|Microsoft-IIS|msrpc|microsoft-ds' \
        scans/tcp-services.txt scans/tcp-aggressive.txt 2>/dev/null; then
        TARGET_IS_WINDOWS=1
    fi

    if ports_lines | grep -q '^88$' && \
       ports_lines | grep -Eq '^(389|636|3268|3269)$' && \
       ports_lines | grep -q '^445$'; then
        TARGET_IS_WINDOWS=1
        TARGET_IS_AD=1
    fi

    AD_DOMAIN="$({ sed -nE 's/.*Domain: ([A-Za-z0-9._-]+).*/\1/p' \
        scans/tcp-services.txt 2>/dev/null || true; } | head -1 || true)"
    AD_DOMAIN="${AD_DOMAIN,,}"
    if [ "$TARGET_IS_AD" = "1" ] && [ -z "$AD_DOMAIN" ]; then
        AD_DOMAIN="${HOST,,}"
    fi

    AD_DC_HOST="$({ grep -Eho 'DNS:[A-Za-z0-9._-]+' scans/tcp-services.txt scans/tcp-aggressive.txt 2>/dev/null || true; } \
        | sed 's/^DNS://' | tr '[:upper:]' '[:lower:]' | head -1 || true)"
    if [ "$TARGET_IS_AD" = "1" ] && [ -z "$AD_DC_HOST" ] && [ -n "$AD_DOMAIN" ]; then
        short_dc="$({ sed -nE 's/.*Service Info: Host: ([A-Za-z0-9_-]+).*/\1/p' \
            scans/tcp-services.txt 2>/dev/null || true; } | head -1 || true)"
        [ -z "$short_dc" ] || AD_DC_HOST="${short_dc,,}.$AD_DOMAIN"
    fi

    if [ -z "$KERBEROS_REALM" ] && [ -n "$AD_DOMAIN" ]; then
        KERBEROS_REALM="${AD_DOMAIN^^}"
    fi

    clock_skew="$({ sed -nE 's/.*clock-skew:[[:space:]]*//p' \
        scans/tcp-services.txt scans/tcp-aggressive.txt 2>/dev/null || true; } \
        | head -1 || true)"
    {
        if [ "$TARGET_IS_AD" = "1" ]; then
            echo "profile=windows-ad-dc"
        elif [ "$TARGET_IS_WINDOWS" = "1" ]; then
            echo "profile=windows"
        else
            echo "profile=generic"
        fi
        echo "domain=$AD_DOMAIN"
        echo "realm=$KERBEROS_REALM"
        echo "dc_hostname=$AD_DC_HOST"
        echo "clock_skew=$clock_skew"
    } | tee scans/target-profile.txt > enum/windows/profile.txt

    if [ "$TARGET_IS_AD" = "1" ]; then
        echo "[+] Active Directory domain controller profile detected."
        echo "[+] Domain: ${AD_DOMAIN:-unknown}"
        echo "[+] Kerberos realm: ${KERBEROS_REALM:-unknown}"
        echo "[+] DC hostname: ${AD_DC_HOST:-unknown}"
        if is_hostname_candidate "$AD_DC_HOST"; then
            echo "$IP $AD_DC_HOST" > enum/ad/hosts-additions.txt
        fi
        if [ -n "$clock_skew" ]; then
            printf '%s\n' "$clock_skew" > enum/ad/clock-skew.txt
            echo "[!] Kerberos clock-skew evidence: $clock_skew"
            echo "[!] Review enum/ad/ntp-query.txt before changing local time."
        fi
        if have ntpdate; then
            run_with_timeout 30 ntpdate -q "$IP" | tee enum/ad/ntp-query.txt || true
        fi
    fi
}

run_web_assessment() {
    local status
    local -a assessor_args=()

    [ "$WEB_ASSESS_RAN" = "0" ] || return 0
    WEB_ASSESS_RAN=1

    if [[ "$WEB_ASSESS" == "1" && "$NUCLEI_ENABLE" == "1" ]] && \
       { [[ -s enum/web/live-web-urls.txt ]] || [[ -s enum/web/discovered-host-web-urls.txt ]]; }; then
        if [[ -f ./web-assess.sh && -f ./web-assess.py ]]; then
            if [[ -n "$WEB_ASSESS_ARGS_FILE" ]]; then mapfile -t assessor_args < "$WEB_ASSESS_ARGS_FILE"; fi
            if [[ -n "$WEB_SESSION_FILE" ]]; then assessor_args+=(--session-file "$WEB_SESSION_FILE"); fi
            if [[ -n "$WEB_REQUESTS_FILE" ]]; then assessor_args+=(--requests-file "$WEB_REQUESTS_FILE"); fi
            if run_with_timeout "$WEB_ASSESS_MAXTIME" bash ./web-assess.sh "${assessor_args[@]}"; then
                echo "[+] Automated web assessment finished; review its coverage limits."
            else
                status=$?
                if [[ "$status" == "1" ]]; then
                    echo "[!] Web assessment produced findings; see enum/web/assessments/."
                else
                    echo "[!] Web assessment incomplete (exit $status); inspect its report/logs."
                fi
            fi
        else
            echo "[!] Web assessment helper missing; initialize using the full repository checkout."
            record_result error 127 "Web assessment helper missing"
        fi
    else
        echo "[i] Web assessment disabled or no web URLs discovered."
        record_result skipped 0 "Web assessment disabled or no web URLs"
    fi
}

add_wordlist() {
    local wordlist="$1"
    local plan_file="$2"

    if [ -n "$wordlist" ] && [ -f "$wordlist" ]; then
        append_unique_line "$wordlist" "$plan_file"
    fi
}

profile_has() {
    local profile_file="$1"
    local name="$2"

    grep -Fxq "$name" "$profile_file" 2>/dev/null
}

ffuf_extensions_arg() {
    local extensions="$1"
    echo "$extensions" | awk -F, '{
        for (i = 1; i <= NF; i++) {
            gsub(/^[.[:space:]]+|[[:space:]]+$/, "", $i)
            if ($i != "") {
                printf "%s.%s", sep, $i
                sep=","
            }
        }
    }'
}

wordlist_line_count() {
    local wordlist="$1"
    if [ -f "$wordlist" ]; then
        awk '!/^[[:space:]]*(#|$)/ { count++ } END { print count+0 }' "$wordlist"
    else
        echo 0
    fi
}

should_scan_web_url() {
    local url="$1"
    local port
    port="$(url_port "$url")"

    # Keep default recon fast: scan normal web ports plus common HTB app ports.
    # Deep mode scans every discovered live web URL.
    if [ "$RECON_DEEP" = "1" ]; then
        return 0
    fi

    case "$port" in
        80|443|8000|8080|8443|3000|5000|9000|9090)
            return 0
            ;;
        *)
            echo "[!] Skipping heavy web fuzzing for $url in default mode. Enable with RECON_DEEP=1."
            return 1
            ;;
    esac
}

detect_web_technologies() {
    local safe_url="$1"
    local profile_file="$2"
    local tmp_file

    tmp_file="$(mktemp)"
    : > "$profile_file"

    for candidate in \
        "enum/web/whatweb-$safe_url.txt" \
        "enum/web/whatweb-host-$safe_url.txt" \
        "enum/web/headers-$safe_url.txt" \
        "enum/web/headers-host-$safe_url.txt" \
        "enum/web/index-$safe_url.html" \
        "enum/web/index-host-$safe_url.html" \
        "enum/web/robots.txt-$safe_url.txt" \
        "enum/web/robots.txt-host-$safe_url.txt" \
        "enum/web/openapi.json-$safe_url.txt" \
        "enum/web/swagger.json-$safe_url.txt"; do
        [ -f "$candidate" ] && cat "$candidate" >> "$tmp_file"
    done

    if grep -Eiq 'Drupal|X-Drupal|drupal-settings-json|/sites/default/|/core/misc/drupal|/misc/drupal\.js' "$tmp_file"; then
        append_unique_line "drupal" "$profile_file"
    fi
    if grep -Eiq 'WordPress|wp-content|wp-includes|xmlrpc\.php' "$tmp_file"; then
        append_unique_line "wordpress" "$profile_file"
    fi
    if grep -Eiq 'Joomla|/media/system/js|com_content|com_users' "$tmp_file"; then
        append_unique_line "joomla" "$profile_file"
    fi
    if grep -Eiq '_next/static|Next\.js|x-powered-by:[[:space:]]*Next' "$tmp_file"; then
        append_unique_line "nextjs" "$profile_file"
    fi
    if grep -Eiq 'Laravel|laravel_session|XSRF-TOKEN' "$tmp_file"; then
        append_unique_line "laravel" "$profile_file"
    fi
    if grep -Eiq 'Spring|JSESSIONID|Whitelabel Error Page|X-Application-Context' "$tmp_file"; then
        append_unique_line "java-spring" "$profile_file"
    fi
    if grep -Eiq 'Tomcat|Apache-Coyote|\.jsp|JSESSIONID' "$tmp_file"; then
        append_unique_line "java-tomcat" "$profile_file"
    fi
    if grep -Eiq 'ASP\.NET|X-AspNet|__VIEWSTATE|\.aspx' "$tmp_file"; then
        append_unique_line "aspnet" "$profile_file"
    fi
    if grep -Eiq 'PHPSESSID|X-Powered-By:[[:space:]]*PHP|\.php' "$tmp_file"; then
        append_unique_line "php" "$profile_file"
    fi
    if grep -Eiq 'swagger|openapi|graphql|/api/' "$tmp_file"; then
        append_unique_line "api" "$profile_file"
    fi

    if [ ! -s "$profile_file" ]; then
        append_unique_line "generic-web" "$profile_file"
    fi

    rm -f "$tmp_file"
}

build_web_wordlist_plan() {
    local profile_file="$1"
    local plan_file="$2"

    : > "$plan_file"
    add_wordlist "$WEB_WORDLIST" "$plan_file"
    add_wordlist "$WEB_FILES_WORDLIST" "$plan_file"

    if profile_has "$profile_file" "drupal"; then
        add_wordlist "$DRUPAL_WORDLIST" "$plan_file"
        add_wordlist "$CMS_WORDLIST" "$plan_file"
    fi
    if profile_has "$profile_file" "wordpress"; then
        add_wordlist "$WORDPRESS_WORDLIST" "$plan_file"
        add_wordlist "$CMS_WORDLIST" "$plan_file"
    fi
    if profile_has "$profile_file" "joomla"; then
        add_wordlist "$JOOMLA_WORDLIST" "$plan_file"
        add_wordlist "$CMS_WORDLIST" "$plan_file"
    fi
    if profile_has "$profile_file" "api"; then
        add_wordlist "$API_WORDLIST" "$plan_file"
    fi

    add_wordlist "$BACKUP_WORDLIST" "$plan_file"
}

web_extensions_for_profile() {
    local profile_file="$1"
    local extensions=""

    # Default mode intentionally avoids huge extension multiplication.
    # Deep mode enables broader extension lists.
    if [ "$RECON_DEEP" = "1" ] || [ "$FEROX_EXTENSIONS" = "1" ]; then
        extensions="txt,html,js,bak,old,zip,tar,gz,conf,config,json,yml,xml,log"
    fi

    if profile_has "$profile_file" "php" || profile_has "$profile_file" "drupal" || profile_has "$profile_file" "wordpress" || profile_has "$profile_file" "joomla" || profile_has "$profile_file" "laravel"; then
        if [ -n "$extensions" ]; then
            extensions="php,$extensions"
        else
            extensions="php"
        fi
    fi
    if profile_has "$profile_file" "aspnet"; then
        if [ -n "$extensions" ]; then
            extensions="aspx,config,$extensions"
        else
            extensions="aspx"
        fi
    fi
    if profile_has "$profile_file" "java-spring" || profile_has "$profile_file" "java-tomcat"; then
        if [ -n "$extensions" ]; then
            extensions="jsp,do,action,$extensions"
        else
            extensions="jsp"
        fi
    fi

    echo "$extensions"
}

run_ferox_plan() {
    local url="$1"
    local safe_url="$2"
    local plan_file="$3"
    local extensions="$4"
    local ran=false
    local count=0
    local label
    local word_count
    local ferox_args=()

    if [ "$WEB_ENUM" != "1" ]; then
        echo "[!] Skipping heavy web enumeration because WEB_ENUM=$WEB_ENUM."
        return 0
    fi

    if [ "$FEROX_ENABLE" != "1" ]; then
        echo "[!] Skipping feroxbuster because FEROX_ENABLE=$FEROX_ENABLE."
        return 0
    fi

    if ! have feroxbuster; then
        return 0
    fi

    if ! should_scan_web_url "$url"; then
        return 0
    fi

    if [ ! -s "$plan_file" ]; then
        echo "[!] Skipping feroxbuster: no usable web wordlists found."
        return 0
    fi

    while read -r wordlist; do
        [ -f "$wordlist" ] || continue

        count=$((count + 1))
        if [ "$count" -gt "$MAX_WEB_WORDLISTS" ]; then
            echo "[!] Ferox wordlist budget reached. Skipping remaining wordlists for $url."
            break
        fi

        word_count="$(wordlist_line_count "$wordlist")"
        label="$(safe_name "$(basename "$wordlist")")"
        ran=true

        ferox_args=(
            -u "$url"
            -w "$wordlist"
            -k
            -d 1
            -t "$FEROX_THREADS"
            -o "enum/web/ferox-$safe_url-$label.txt"
        )

        if [ -n "$extensions" ]; then
            ferox_args+=(-x "$extensions")
        fi

        if [ "$RECON_DEEP" = "1" ] || [ "$FEROX_COLLECT" = "1" ]; then
            ferox_args+=(--collect-backups)
        fi

        echo "[+] Running fast-bounded feroxbuster with $wordlist"
        echo "[+] Ferox budget: max ${FEROX_MAXTIME}s, threads ${FEROX_THREADS}, depth 1, wordlist lines ${word_count}, extensions '${extensions:-none}'"
        run_with_timeout "$FEROX_MAXTIME" feroxbuster "${ferox_args[@]}" || true
    done < "$plan_file"

    if [ "$ran" = false ]; then
        echo "[!] Skipping feroxbuster: planned wordlists were not present on disk."
    fi
}

run_ffuf_content_plan() {
    local url="$1"
    local safe_url="$2"
    local plan_file="$3"
    local extensions="$4"
    local profile_file="$5"
    local ffuf_ext
    local count=0
    local label

    if [ "$WEB_ENUM" != "1" ]; then
        echo "[!] Skipping ffuf content discovery because WEB_ENUM=$WEB_ENUM."
        return 0
    fi

    if ! have ffuf || [ ! -s "$plan_file" ]; then
        return 0
    fi

    if ! should_scan_web_url "$url"; then
        return 0
    fi

    if [ "$FFUF_CONTENT" != "1" ] && [ "$RECON_DEEP" != "1" ]; then
        echo "[!] Skipping ffuf content discovery by default to avoid long duplicate scans."
        echo "[!] To enable it: RECON_DEEP=1 FFUF_CONTENT=1 ./recon.sh"
        return 0
    fi

    ffuf_ext="$(ffuf_extensions_arg "$extensions")"

    while read -r wordlist; do
        [ -f "$wordlist" ] || continue

        # API wordlists already contain endpoint-style entries; adding many extensions
        # multiplies requests without much value. CMS/generic content gets extensions.
        local extra_args=()
        if profile_has "$profile_file" "api" && [[ "$wordlist" == *"/api/"* ]]; then
            extra_args=()
        elif [ -n "$ffuf_ext" ]; then
            extra_args=(-e "$ffuf_ext")
        else
            extra_args=()
        fi

        count=$((count + 1))
        if [ "$count" -gt "$MAX_FFUF_WORDLISTS" ]; then
            echo "[!] FFUF content wordlist budget reached. Skipping remaining wordlists for $url."
            break
        fi

        label="$(safe_name "$(basename "$wordlist")")"
        echo "[+] Running bounded ffuf content discovery with $wordlist"
        run_with_timeout "$FFUF_MAXTIME" ffuf \
            -noninteractive \
            -ac \
            -t "$FFUF_THREADS" \
            -rate "$FFUF_RATE" \
            -maxtime "$FFUF_MAXTIME" \
            -w "$wordlist" \
            -u "$url/FUZZ" \
            "${extra_args[@]}" \
            -of json \
            -o "enum/web/ffuf-content-$safe_url-$label.json" || true
    done < "$plan_file"
}

run_vhost_ffuf() {
    local url="$1"
    local safe_url="$2"
    local scheme port scan_key base_domain safe_base output_file label vhost_wordlist

    if [ "$WEB_ENUM" != "1" ]; then
        echo "[!] Skipping ffuf vhost discovery because WEB_ENUM=$WEB_ENUM."
        return 0
    fi

    if ! have ffuf; then
        return 0
    fi

    if ! should_scan_web_url "$url"; then
        return 0
    fi

    if [ "$FFUF_VHOST" != "1" ]; then
        echo "[!] Skipping ffuf vhost discovery because FFUF_VHOST=$FFUF_VHOST."
        return 0
    fi

    if [ ! -f "$PRIORITY_VHOST_WORDLIST" ] && [ ! -f "$DNS_WORDLIST" ]; then
        echo "[!] Skipping ffuf vhost discovery: no vhost wordlist found."
        return 0
    fi

    scheme="$(url_scheme "$url")"
    port="$(url_port "$url")"

    collect_vhost_base_domains "$url"

    if [ ! -s enum/dns/vhost-base-domains.txt ]; then
        echo "[!] No vhost base domains available for ffuf."
        return 0
    fi

    while read -r base_domain; do
        [ -n "$base_domain" ] || continue
        is_hostname_candidate "$base_domain" || continue

        safe_base="$(safe_name "$base_domain")"

        for vhost_wordlist in "$PRIORITY_VHOST_WORDLIST" "$DNS_WORDLIST"; do
            [ -n "$vhost_wordlist" ] || continue
            [ -f "$vhost_wordlist" ] || continue

            label="$(safe_name "$(basename "$vhost_wordlist")")"
            scan_key="$scheme/$port/$base_domain/$vhost_wordlist"
            output_file="enum/web/ffuf-vhosts-$safe_url-$safe_base-$label.json"

            if [ "${VHOST_SCANS_DONE[$scan_key]:-0}" = "1" ]; then
                echo "[!] Skipping duplicate ffuf vhost scan for $scheme/$port base $base_domain wordlist $label."
                continue
            fi
            echo "[+] Running bounded ffuf vhost discovery with $vhost_wordlist against base domain: $base_domain"
            if run_with_timeout "$FFUF_MAXTIME" ffuf \
                -noninteractive \
                -ac \
                -t "$FFUF_THREADS" \
                -rate "$FFUF_RATE" \
                -maxtime "$FFUF_MAXTIME" \
                -w "$vhost_wordlist" \
                -u "$url/" \
                -H "Host: FUZZ.$base_domain" \
                -of json \
                -o "$output_file"; then
                VHOST_SCANS_DONE["$scan_key"]=1
            else
                echo "[!] ffuf vhost scan did not complete: $base_domain ($label). It may be retried."
            fi
        done
    done < enum/dns/vhost-base-domains.txt
}

run_cms_specific_checks() {
    local url="$1"
    local safe_url="$2"
    local profile_file="$3"

    if profile_has "$profile_file" "drupal"; then
        echo "[+] Drupal profile detected; checking Drupal-specific paths and scanners."
        for path in CHANGELOG.txt core/CHANGELOG.txt user/login user/register node sites/default/files/ sites/default/settings.php; do
            safe_path="$(echo "$path" | sed 's#[/]#_#g')"
            run_fetch_curl -k -s -i --connect-timeout 5 --max-time "$CURL_MAXTIME" \
                "$url/$path" -o "enum/web/drupal-$safe_path-$safe_url.txt" || true
        done
        if have droopescan; then
            run_with_timeout 900 droopescan scan drupal -u "$url" | tee "enum/web/droopescan-$safe_url.txt" || true
        fi
        # Nuclei templates run through the unified assessor after discovery.
    fi

    if profile_has "$profile_file" "wordpress" && have wpscan; then
        echo "[+] WordPress profile detected; running bounded WPScan."
        run_with_timeout 900 wpscan --url "$url" --disable-tls-checks --enumerate vp,vt,u -o "enum/web/wpscan-$safe_url.txt" || true
    fi

    if profile_has "$profile_file" "joomla" && have joomscan; then
        echo "[+] Joomla profile detected; running bounded joomscan."
        run_with_timeout 900 joomscan -u "$url" | tee "enum/web/joomscan-$safe_url.txt" || true
    fi

    if profile_has "$profile_file" "api"; then
        echo "[+] API indicators detected; checking common API docs and GraphQL paths."
        for path in api api/v1 api/v2 graphql graphiql swagger swagger-ui openapi.json swagger.json docs redoc; do
            safe_path="$(echo "$path" | sed 's#[/]#_#g')"
            run_fetch_curl -k -s -i --connect-timeout 5 --max-time "$CURL_MAXTIME" \
                "$url/$path" -o "enum/web/api-$safe_path-$safe_url.txt" || true
        done
    fi
}

extract_dns_hostnames() {
    local domain domain_regex evidence_file tmp raw_hosts

    mkdir -p enum/dns
    tmp="$(mktemp)"
    raw_hosts="$(mktemp)"
    trap 'rm -f "$tmp" "$raw_hosts"' RETURN

    collect_vhost_base_domains

    : > enum/dns/discovered-hostnames.txt
    : > enum/dns/discovered-subdomains.txt
    : > enum/dns/hosts-additions.txt

    # 1) Extract hostnames ending in every known base domain, not only $HOST.
    while read -r domain; do
        [ -n "$domain" ] || continue
        is_hostname_candidate "$domain" || continue

        domain_regex="$(printf '%s' "$domain" | sed 's/[][\.^$*+?{}|()]/\\&/g')"
        for evidence_file in \
            enum/dns/dig-a.txt enum/dns/dig-ns.txt enum/dns/dig-mx.txt \
            enum/dns/dnsrecon.txt enum/dns/gobuster-dns.txt \
            enum/web/headers-*.txt enum/web/index-*.html enum/web/js-interesting-*.txt; do
            [ -f "$evidence_file" ] || continue
            grep -hoE "([A-Za-z0-9_-]+\.)*$domain_regex" "$evidence_file" 2>/dev/null >> "$raw_hosts" || true
        done
        echo "$domain" >> "$raw_hosts"
    done < enum/dns/vhost-base-domains.txt

    # 2) Parse ffuf JSON directly because .host is the most reliable source.
    if have jq; then
        for f in enum/web/ffuf-vhosts-*.json enum/dns/ffuf-vhosts-*.json; do
            [ -f "$f" ] || continue
            jq -r '.results[]? | .host // empty' "$f" 2>/dev/null >> "$raw_hosts" || true
        done
    else
        grep -RhoE '"host"[[:space:]]*:[[:space:]]*"[A-Za-z0-9._-]+"' enum/web enum/dns 2>/dev/null \
            | sed -E 's/.*"host"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' >> "$raw_hosts" || true
    fi

    sed 's/^[*.]*//; s/[[:space:]]//g; s/:$//; s/\.$//' "$raw_hosts" \
        | tr '[:upper:]' '[:lower:]' \
        | grep -E '^[a-z0-9._-]+\.[a-z0-9._-]+$' \
        | grep -Ev '^([0-9]{1,3}\.){3}[0-9]{1,3}$' \
        | grep -Eiv '^(fuzz|hostmaster)\.' \
        | sort -u > enum/dns/discovered-hostnames.txt || true

    cp enum/dns/discovered-hostnames.txt "$tmp"
    while read -r domain; do
        [ -n "$domain" ] || continue
        grep -Fxv "$domain" "$tmp" > "$tmp.filtered" || true
        mv "$tmp.filtered" "$tmp"
    done < enum/dns/vhost-base-domains.txt
    cp "$tmp" enum/dns/discovered-subdomains.txt

    while read -r name; do
        [ -n "$name" ] || continue
        is_web_hostname_candidate "$name" || continue
        echo "$IP $name"
    done < enum/dns/discovered-hostnames.txt > enum/dns/hosts-additions.txt
}

probe_discovered_hostnames() {
    local ports_to_probe name port scheme url code

    : > enum/web/discovered-host-web-probe.txt
    : > enum/web/discovered-host-web-urls.txt

    if [ ! -s enum/dns/discovered-hostnames.txt ]; then
        return 0
    fi

    # An SSH-only target used to exit here under pipefail because grep found no
    # common HTTP port. Also include HTTP services found on nonstandard ports.
    ports_to_probe="$({
        ports_lines | grep -E '^(80|443|8000|8080|8443|3000|5000|9000|9090)$' || true
        while read -r url; do
            [ -n "$url" ] && url_port "$url"
        done < enum/web/live-web-urls.txt
    } | sort -nu | tr '\n' ' ')"
    [ -n "$ports_to_probe" ] || return 0

    while read -r name; do
        [ -z "$name" ] && continue
        if ! is_web_hostname_candidate "$name"; then
            echo "[i] Keeping DNS infrastructure name as evidence, not probing it as a web vhost: $name"
            continue
        fi
        for port in $ports_to_probe; do
            for scheme in http https; do
                if [[ "$scheme:$port" == "http:80" || "$scheme:$port" == "https:443" ]]; then
                    url="$scheme://$name"
                else
                    url="$scheme://$name:$port"
                fi

                if ! url_in_scope "$url"; then
                    record_result skipped 0 "Discovered hostname requires explicit scope approval"
                    continue
                fi
                code="$(curl -k -s -o /dev/null -w "%{http_code}" --connect-timeout 2 --max-time 5 --resolve "$name:$port:$IP" "$url" || true)"
                echo "$url $code" | tee -a enum/web/discovered-host-web-probe.txt

                if [[ "$code" =~ ^[1-5][0-9]{2}$ ]]; then
                    append_unique_line "$url" enum/web/discovered-host-web-urls.txt
                fi
            done
        done
    done < enum/dns/discovered-hostnames.txt
}

# Validate dependencies and configuration before rotating or truncating evidence.
for required in nmap timeout curl "$RECON_PYTHON"; do
    if ! have "$required"; then echo "[-] Required command missing: $required" >&2; exit 2; fi
done
if ! "$RECON_PYTHON" -I -c 'import sys; raise SystemExit(sys.version_info < (3, 10))'; then
    echo "[-] HTB_PYTHON must select Python 3.10 or newer." >&2
    exit 2
fi
for knob in NMAP_MAXTIME SERVICE_ENUM_MAXTIME WEB_PROBE_MAXTIME CURL_MAXTIME ANALYZER_MAXTIME ARCHIVE_MAXTIME WEB_ASSESS_MAXTIME SCANNER_UPDATE_MAXTIME NIKTO_MAXTIME NUCLEI_MAXTIME MQTT_ENUM_MAXTIME FEROX_MAXTIME FFUF_MAXTIME MAX_JS_FILES MAX_WEB_URLS MAX_WEB_WORDLISTS MAX_FFUF_WORDLISTS FFUF_THREADS FFUF_RATE FEROX_THREADS VULN_TIMEOUT MAX_VULN_RESULTS; do
    if [[ ! "${!knob}" =~ ^[1-9][0-9]*$ ]]; then echo "[-] $knob must be a positive integer." >&2; exit 2; fi
done
if [[ -n "$KERBEROS_USERDB" && ! -f "$KERBEROS_USERDB" ]]; then
    echo "[-] Kerberos user list does not exist: $KERBEROS_USERDB" >&2
    exit 2
fi
for input in "$WEB_SESSION_FILE" "$WEB_REQUESTS_FILE" "$WEB_ASSESS_ARGS_FILE"; do
    if [[ -n "$input" && ! -f "$input" ]]; then echo "[-] Web assessment input file does not exist: $input" >&2; exit 2; fi
done
if ! url_in_scope "http://$IP/"; then
    echo "[-] Target IP is excluded or missing from explicit scope; correct scope.json before collection." >&2
    exit 2
fi
if ! mkdir .recon.lock 2>/dev/null; then
    echo "[-] Another run holds .recon.lock; confirm it has stopped before removing the lock." >&2
    exit 2
fi
trap finish_run EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
"$RECON_PYTHON" -I - "$BOX" "$IP" "$HOST" <<'PREPARERUN'
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import sys
import uuid
root = Path.cwd().resolve()
names = ['scans', 'enum', 'reports', 'summary.md', 'recon-analysis.md', 'overview.md', 'overview.json',
         'run-status.json', 'run-stages.tsv', 'recon-console.log', 'run-target.env', 'run-scope.json', 'run-sources']
for name in names + ['runs']:
    path = root / name
    if path.is_symlink() or path.resolve().parent != root:
        raise SystemExit('Refusing linked output path: ' + name)
existing = [root / name for name in names if (root / name).exists()]
has_evidence = any(p.is_file() or (p.is_dir() and any(q.is_file() for q in p.rglob('*'))) for p in existing)
if has_evidence:
    previous = 'legacy-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    status = root / 'run-status.json'
    if status.is_file():
        try:
            value = json.loads(status.read_text(encoding='utf-8')).get('run_id', '')
            if re.fullmatch(r'[A-Za-z0-9_-]+', value): previous = value
        except (ValueError, OSError): pass
    destination = root / 'runs' / (previous + '-' + uuid.uuid4().hex[:8])
    destination.mkdir(parents=True)
    for path in existing:
        shutil.move(str(path), str(destination / path.name))
    if (destination / 'run-target.env').exists():
        shutil.copyfile(destination / 'run-target.env', destination / '.target.env')
    if (destination / 'run-scope.json').exists():
        shutil.copyfile(destination / 'run-scope.json', destination / 'scope.json')
run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
shutil.copyfile(root / '.target.env', root / 'run-target.env')
if (root / 'scope.json').is_file(): shutil.copyfile(root / 'scope.json', root / 'run-scope.json')
sources = root / 'run-sources'
sources.mkdir(exist_ok=True)
for name in ['recon.sh', 'web-assess.sh', 'web-assess.py', 'tools/analyze-recon.py']:
    path = root / name
    if path.is_file(): shutil.copyfile(path, sources / path.name)
report = {'schema_version': 1, 'run_id': run_id, 'target': dict(zip(['box', 'ip', 'host'], sys.argv[1:])),
          'started_at': datetime.now(timezone.utc).isoformat(), 'status': 'running', 'stages': []}
(root / 'run-status.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
(root / 'run-stages.tsv').write_text('', encoding='utf-8')
PREPARERUN
RUN_READY=1
exec > >(tee recon-console.log) 2>&1
record_result started 0 "preflight and scanner data"

WEB_WORDLIST="$(pick_first_file \
    /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt \
    /usr/share/seclists/Discovery/Web-Content/common.txt \
    /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
    /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt \
    /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
    || true)"

WEB_FILES_WORDLIST="$(pick_first_file \
    /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
    /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt \
    /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt \
    || true)"

CMS_WORDLIST="$(pick_first_file \
    /usr/share/seclists/Discovery/Web-Content/CMS/cms.txt \
    /usr/share/wordlists/seclists/Discovery/Web-Content/CMS/cms.txt \
    || true)"

DRUPAL_WORDLIST="$(pick_first_file \
    /usr/share/seclists/Discovery/Web-Content/CMS/Drupal.txt \
    /usr/share/wordlists/seclists/Discovery/Web-Content/CMS/Drupal.txt \
    /usr/share/seclists/Discovery/Web-Content/Drupal.txt \
    || true)"

WORDPRESS_WORDLIST="$(pick_first_file \
    /usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt \
    /usr/share/seclists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt \
    /usr/share/wordlists/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt \
    || true)"

JOOMLA_WORDLIST="$(pick_first_file \
    /usr/share/seclists/Discovery/Web-Content/CMS/Joomla.txt \
    /usr/share/wordlists/seclists/Discovery/Web-Content/CMS/Joomla.txt \
    || true)"

API_WORDLIST="$(pick_first_file \
    /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
    /usr/share/seclists/Discovery/Web-Content/api/actions.txt \
    /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt \
    || true)"

BACKUP_WORDLIST="$(pick_first_file \
    /usr/share/seclists/Discovery/Web-Content/common-and-french.txt \
    /usr/share/seclists/Discovery/Web-Content/big.txt \
    /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt \
    || true)"

DNS_WORDLIST="$(pick_first_file \
    /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt \
    || true)"

PRIORITY_VHOST_WORDLIST="enum/dns/priority-vhosts.txt"
mkdir -p enum/dns
cat > "$PRIORITY_VHOST_WORDLIST" <<'PRIORITYVHOSTS'
www
admin
administrator
adm
app
apps
api
api-dev
dev
devel
development
test
testing
stage
staging
beta
portal
login
auth
sso
dashboard
console
internal
intranet
monitor
monitoring
zabbix
grafana
prometheus
kibana
elastic
jenkins
teamcity
ci
build
git
gitlab
gitea
repo
repos
status
helpdesk
support
backup
backups
old
legacy
PRIORITYVHOSTS

SNMP_WORDLIST="$(pick_first_file \
    /usr/share/seclists/Discovery/SNMP/snmp.txt \
    /usr/share/wordlists/seclists/Discovery/SNMP/snmp.txt \
    || true)"

mkdir -p scans enum/{web,dns,smb,ftp,nfs,snmp,ldap,kerberos,rpc,winrm,rdp,mssql,ssh,windows,ad,mqtt,other}
: > scans/tcp-full.txt
: > scans/tcp-services.txt
: > scans/udp-top100.txt
: > enum/dns/vhost-base-domains.txt
append_unique_line "$HOST" enum/dns/vhost-base-domains.txt

echo "[+] Starting recon for $BOX / $IP"
echo "[+] Hostname: $HOST"
echo "[+] Started at: $START_TIME"
echo "[+] Runtime knobs: RECON_DEEP=$RECON_DEEP WEB_ENUM=$WEB_ENUM WEB_ASSESS=$WEB_ASSESS WEB_ASSESS_MAXTIME=$WEB_ASSESS_MAXTIME FEROX_ENABLE=$FEROX_ENABLE FEROX_EXTENSIONS=$FEROX_EXTENSIONS FEROX_COLLECT=$FEROX_COLLECT FEROX_MAXTIME=$FEROX_MAXTIME FEROX_THREADS=$FEROX_THREADS FFUF_CONTENT=$FFUF_CONTENT FFUF_VHOST=$FFUF_VHOST FFUF_MAXTIME=$FFUF_MAXTIME FFUF_THREADS=$FFUF_THREADS FFUF_RATE=$FFUF_RATE NIKTO_ENABLE=$NIKTO_ENABLE NIKTO_MAXTIME=$NIKTO_MAXTIME NUCLEI_ENABLE=$NUCLEI_ENABLE NUCLEI_MAXTIME=$NUCLEI_MAXTIME VULN_SCAN=$VULN_SCAN MQTT_ALL_TOPICS=$MQTT_ALL_TOPICS MQTT_ENUM_MAXTIME=$MQTT_ENUM_MAXTIME NMAP_MAXTIME=$NMAP_MAXTIME SERVICE_ENUM_MAXTIME=$SERVICE_ENUM_MAXTIME WEB_PROBE_MAXTIME=$WEB_PROBE_MAXTIME CURL_MAXTIME=$CURL_MAXTIME ANALYZER_MAXTIME=$ANALYZER_MAXTIME ARCHIVE_MAXTIME=$ARCHIVE_MAXTIME UPDATE_SCANNER_DATA=$UPDATE_SCANNER_DATA SCANNER_UPDATE_MAXTIME=$SCANNER_UPDATE_MAXTIME MAX_WEB_URLS=$MAX_WEB_URLS MAX_WEB_WORDLISTS=$MAX_WEB_WORDLISTS MAX_FFUF_WORDLISTS=$MAX_FFUF_WORDLISTS VHOST_SUFFIXES=$VHOST_SUFFIXES ONLINE_VULN_CHECK=$ONLINE_VULN_CHECK VULN_TIMEOUT=$VULN_TIMEOUT MAX_VULN_RESULTS=$MAX_VULN_RESULTS"

echo
echo "=============================="
echo "[+] 0. Tool availability check"
echo "=============================="

for TOOL in nmap timeout whatweb feroxbuster ffuf nikto curl dig dnsrecon gobuster smbclient enum4linux-ng enum4linux smbmap showmount rpcinfo rpcclient impacket-rpcdump rpcdump.py mosquitto_sub snmpwalk onesixtyone ldapsearch ntpdate jq zip nc openssl ftp httpx nuclei netexec crackmapexec droopescan wpscan joomscan rg; do
    if have "$TOOL"; then
        echo "[+] $TOOL found"
    else
        echo "[-] $TOOL not found"
        record_result skipped 0 "$TOOL unavailable"
    fi
done | tee scans/tool-check.txt

echo
echo "================================"
echo "[+] 0.5 Scanner-data refresh"
echo "================================"

refresh_scanner_data

if ! have nmap || ! have timeout; then
    echo "[-] nmap and timeout are required."
    exit 1
fi

echo
if [ -n "$WEB_WORDLIST" ]; then
    echo "[+] Web wordlist: $WEB_WORDLIST"
else
    echo "[!] No web directory wordlist found. Feroxbuster will be skipped."
fi

echo "[+] Optional web files wordlist: ${WEB_FILES_WORDLIST:-not found}"
echo "[+] Optional CMS wordlist: ${CMS_WORDLIST:-not found}"
echo "[+] Optional Drupal wordlist: ${DRUPAL_WORDLIST:-not found}"
echo "[+] Optional WordPress wordlist: ${WORDPRESS_WORDLIST:-not found}"
echo "[+] Optional Joomla wordlist: ${JOOMLA_WORDLIST:-not found}"
echo "[+] Optional API wordlist: ${API_WORDLIST:-not found}"
echo "[+] Optional backup wordlist: ${BACKUP_WORDLIST:-not found}"

if [ -n "$DNS_WORDLIST" ]; then
    echo "[+] DNS wordlist: $DNS_WORDLIST"
else
    echo "[!] No DNS subdomain wordlist found. ffuf/gobuster DNS wordlist modes will be skipped."
fi

if [ -n "$SNMP_WORDLIST" ]; then
    echo "[+] SNMP wordlist: $SNMP_WORDLIST"
else
    echo "[!] No SNMP community wordlist found. onesixtyone will be skipped."
fi

echo
echo "=============================="
echo "[+] 1. TCP full port discovery"
echo "=============================="
show_progress 1 "TCP full port discovery"

: > scans/open-tcp-ports.txt
# These manifests describe this run. Do not leave prior web targets available
# to downstream assessment when a later scan finds no open ports or fails.
: > enum/web/live-web-urls.txt
: > enum/web/discovered-host-web-urls.txt
TCP_DISCOVERY_STATUS=0
run_with_timeout "$NMAP_MAXTIME" nmap \
    -p- --min-rate 5000 -Pn "$IP" -oN scans/tcp-full.txt || TCP_DISCOVERY_STATUS=$?

PORTS="$(awk '$1 ~ /^[0-9]+\/tcp$/ && $2 == "open" { sub(/\/tcp$/, "", $1); print $1 }' scans/tcp-full.txt | paste -sd, -)"

if [ -z "$PORTS" ]; then
    echo "[-] No open TCP ports found."
    if [ "$TCP_DISCOVERY_STATUS" -ne 0 ]; then
        echo "[!] TCP discovery exited with status $TCP_DISCOVERY_STATUS; its result may be incomplete."
    fi
    echo "[+] Continuing with UDP discovery, relevant enumeration, and analysis."
fi

echo "[+] Open TCP ports: $PORTS"
if [[ -n "$PORTS" ]]; then printf '%s\n' "$PORTS" > scans/open-tcp-ports.txt; fi

echo
echo "======================================"
echo "[+] 2. TCP service/version enumeration"
echo "======================================"
show_progress 2 "TCP service/version enumeration"

if [[ -n "$PORTS" ]]; then
run_with_timeout "$NMAP_MAXTIME" nmap \
    -sC -sV -Pn -p "$PORTS" "$IP" \
    -oN scans/tcp-services.txt -oX scans/tcp-services.xml || true
run_with_timeout "$NMAP_MAXTIME" nmap \
    -A -Pn -p "$PORTS" "$IP" -oN scans/tcp-aggressive.txt || true
run_with_timeout "$NMAP_MAXTIME" nmap \
    -sV --script "safe and not broadcast" -Pn -p "$PORTS" "$IP" \
    -oN scans/tcp-default-safe-scripts.txt || true
else
    record_result skipped 0 "No confirmed open TCP ports"
fi

detect_target_profile

echo
echo "=============================="
echo "[+] 3. UDP top ports scan"
echo "=============================="
show_progress 3 "UDP top ports scan"

run_with_timeout "$NMAP_MAXTIME" nmap \
    -sU -Pn --top-ports 100 "$IP" -oN scans/udp-top100.txt || true

echo
echo "=============================================="
echo "[+] 4. Web service discovery on all TCP ports"
echo "=============================================="
show_progress 4 "Web service discovery"

: > enum/web/web-candidates.txt
: > enum/web/live-web-urls.txt
: > enum/web/httpx-web-services.txt
: > enum/web/curl-web-probe.txt

for PORT in $(ports_lines); do
    if ! is_web_candidate_port "$PORT"; then
        echo "[i] Excluding non-web service port from HTTP probing: $PORT"
        record_result skipped 0 "Non-web service excluded from HTTP probing"
        continue
    fi

    echo "http://$IP:$PORT" >> enum/web/web-candidates.txt
    echo "https://$IP:$PORT" >> enum/web/web-candidates.txt
done

USE_HTTPX=false

if have httpx; then
    if run_with_timeout 10 httpx -h 2>&1 | grep -- '-l' >/dev/null; then
        USE_HTTPX=true
    else
        echo "[!] httpx found, but it does not appear to be ProjectDiscovery httpx. Falling back to curl."
    fi
else
    echo "[-] httpx not found. Falling back to curl-based probing."
fi

if [ "$USE_HTTPX" = true ]; then
    echo "[+] ProjectDiscovery httpx found. Probing all open TCP ports for HTTP/HTTPS."

    run_with_timeout "$WEB_PROBE_MAXTIME" httpx \
        -l enum/web/web-candidates.txt \
        -title \
        -tech-detect \
        -status-code \
        -web-server \
        -content-length \
        -silent \
        -o enum/web/httpx-web-services.txt || true

    awk '{print $1}' enum/web/httpx-web-services.txt | sort -u > enum/web/live-web-urls.txt || true
fi

if [ ! -s enum/web/live-web-urls.txt ]; then
    echo "[+] Running curl-based HTTP/HTTPS probing."

    while read -r URL; do
        [ -z "$URL" ] && continue

        CODE="$(curl -k -s -o /dev/null -w "%{http_code}" --connect-timeout 2 --max-time 4 "$URL" || true)"
        echo "$URL $CODE" | tee -a enum/web/curl-web-probe.txt

        if [[ "$CODE" =~ ^[1-5][0-9]{2}$ ]]; then
            echo "$URL" >> enum/web/live-web-urls.txt
        fi
    done < enum/web/web-candidates.txt

    sort -u -o enum/web/live-web-urls.txt enum/web/live-web-urls.txt || true
fi

echo "[+] Live web URLs discovered:"
cat enum/web/live-web-urls.txt || true

echo
echo "=============================="
echo "[+] 5. Web enumeration"
echo "=============================="
show_progress 5 "Web enumeration"

if [ -s enum/web/live-web-urls.txt ]; then
    WEB_URL_COUNT=0
    while read -r URL; do
        [ -z "$URL" ] && continue

        if ! url_in_scope "$URL"; then record_result skipped 0 "Web URL outside approved scope"; continue; fi
        WEB_URL_COUNT=$((WEB_URL_COUNT + 1))
        if [ "$RECON_DEEP" != "1" ] && [ "$WEB_URL_COUNT" -gt "$MAX_WEB_URLS" ]; then
            echo "[!] Web URL budget reached at MAX_WEB_URLS=$MAX_WEB_URLS. Enable full coverage with RECON_DEEP=1."
            break
        fi

        SAFE_URL="$(safe_name "$URL")"
        PORT="$(url_port "$URL")"
        SCHEME="$(url_scheme "$URL")"

        if [[ "$SCHEME:$PORT" == "http:80" || "$SCHEME:$PORT" == "https:443" ]]; then
            HOST_URL="$SCHEME://$HOST"
        else
            HOST_URL="$SCHEME://$HOST:$PORT"
        fi

        echo
        echo "[+] Web target: $URL"
        echo "[+] Host URL candidate: $HOST_URL"

        if have whatweb; then
            run_with_timeout "$WEB_PROBE_MAXTIME" whatweb --follow-redirect=never "$URL" \
                | tee "enum/web/whatweb-$SAFE_URL.txt" || true
            if url_in_scope "$HOST_URL"; then
                run_with_timeout "$WEB_PROBE_MAXTIME" whatweb --follow-redirect=never "$HOST_URL" \
                    | tee "enum/web/whatweb-host-$SAFE_URL.txt" || true
            fi
        fi

        if have curl; then
            run_fetch_curl -k -I --connect-timeout 5 --max-time "$CURL_MAXTIME" "$URL" \
                | tee "enum/web/headers-$SAFE_URL.txt" || true
            if url_in_scope "$HOST_URL"; then
                run_fetch_curl -k -I --connect-timeout 5 --max-time "$CURL_MAXTIME" -H "Host: $HOST" "$URL" \
                    | tee "enum/web/headers-host-$SAFE_URL.txt" || true
            fi
            run_fetch_curl -k -s --connect-timeout 5 --max-time "$CURL_MAXTIME" \
                "$URL" -o "enum/web/index-$SAFE_URL.html" || true
            if url_in_scope "$HOST_URL"; then
                run_fetch_curl -k -s --connect-timeout 5 --max-time "$CURL_MAXTIME" -H "Host: $HOST" \
                    "$URL" -o "enum/web/index-host-$SAFE_URL.html" || true
            fi

            for WEBPATH in robots.txt sitemap.xml security.txt .well-known/security.txt .well-known/jwks.json jwks.json openapi.json swagger.json api-docs; do
                SAFE_PATH="$(echo "$WEBPATH" | sed 's#[/]#_#g')"
                run_fetch_curl -k -s -i --connect-timeout 5 --max-time "$CURL_MAXTIME" \
                    "$URL/$WEBPATH" -o "enum/web/${SAFE_PATH}-$SAFE_URL.txt" || true
                if url_in_scope "$HOST_URL"; then
                    run_fetch_curl -k -s -i --connect-timeout 5 --max-time "$CURL_MAXTIME" -H "Host: $HOST" \
                        "$URL/$WEBPATH" -o "enum/web/${SAFE_PATH}-host-$SAFE_URL.txt" || true
                fi
            done
        fi

        collect_vhost_base_domains "$URL" "$HOST_URL"
        echo "[+] Vhost base domains currently known:"
        sed 's/^/    - /' enum/dns/vhost-base-domains.txt 2>/dev/null || true

        echo "[+] Extracting JavaScript references"

        for HTML in "enum/web/index-$SAFE_URL.html" "enum/web/index-host-$SAFE_URL.html"; do
            [ -f "$HTML" ] || continue
            grep -Eo 'src="[^"]+\.js[^"]*"' "$HTML" 2>/dev/null
        done \
            | cut -d'"' -f2 \
            | sort -u \
            | tee "enum/web/js-files-$SAFE_URL.txt" || true

        JS_COUNT=0
        while read -r JS; do
            [ -z "$JS" ] && continue
            JS_COUNT=$((JS_COUNT + 1))
            if [[ "$JS_COUNT" -gt "$MAX_JS_FILES" ]]; then record_result skipped 0 "JavaScript file budget reached"; break; fi

            if [[ "$JS" == http* ]]; then
                JS_URL="$JS"
            elif [[ "$JS" == //* ]]; then
                JS_URL="$SCHEME:$JS"
            elif [[ "$JS" == /* ]]; then
                JS_URL="$SCHEME://$IP:$PORT$JS"
            else
                JS_URL="$URL/$JS"
            fi

            if ! url_in_scope "$JS_URL"; then
                record_result skipped 0 "External JavaScript reference excluded from scope"
                continue
            fi
            JS_SAFE_NAME="$(safe_name "$JS_URL")"

            if have curl; then
                run_fetch_curl -k -s --connect-timeout 5 --max-time "$CURL_MAXTIME" \
                    "$JS_URL" -o "enum/web/js-$SAFE_URL-$JS_SAFE_NAME" || true
                if url_in_scope "$HOST_URL"; then
                    run_fetch_curl -k -s --connect-timeout 5 --max-time "$CURL_MAXTIME" -H "Host: $HOST" \
                        "$JS_URL" -o "enum/web/js-host-$SAFE_URL-$JS_SAFE_NAME" || true
                fi
            fi
        done < "enum/web/js-files-$SAFE_URL.txt"

        echo "[+] Grepping downloaded JavaScript for interesting strings (noise-limited)"
        find enum/web -maxdepth 1 -type f \
            \( -name "js-$SAFE_URL-*" -o -name "js-host-$SAFE_URL-*" \) \
            ! -name "*tailwind*" \
            ! -name "*polyfills*" \
            ! -name "*webpack*" \
            ! -name "*.map" \
            -print0 2>/dev/null \
            | xargs -0 grep -HniI -E "api|admin|login|token|jwt|auth|secret|\bkey\b|debug|dashboard|credentials?|password|jwks|jwe|jws|pac4j|fetch|axios|/api/|localStorage|sessionStorage" 2>/dev/null \
            | truncate_lines \
            | tee "enum/web/js-interesting-$SAFE_URL.txt" || true

        TECH_PROFILE="enum/web/technology-profile-$SAFE_URL.txt"
        WORDLIST_PLAN="enum/web/wordlists-$SAFE_URL.txt"

        detect_web_technologies "$SAFE_URL" "$TECH_PROFILE"
        build_web_wordlist_plan "$TECH_PROFILE" "$WORDLIST_PLAN"
        WEB_EXTENSIONS="$(web_extensions_for_profile "$TECH_PROFILE")"

        echo "[+] Detected web technology profile:"
        sed 's/^/    - /' "$TECH_PROFILE" || true
        echo "[+] Planned wordlists:"
        sed 's/^/    - /' "$WORDLIST_PLAN" || true
        echo "[+] Extension set: $WEB_EXTENSIONS"

        run_ferox_plan "$URL" "$SAFE_URL" "$WORDLIST_PLAN" "$WEB_EXTENSIONS"
        run_ffuf_content_plan "$URL" "$SAFE_URL" "$WORDLIST_PLAN" "$WEB_EXTENSIONS" "$TECH_PROFILE"
        run_vhost_ffuf "$URL" "$SAFE_URL"
        if [[ "$WEB_ENUM" == "1" ]]; then
            run_cms_specific_checks "$URL" "$SAFE_URL" "$TECH_PROFILE"
        fi

        if [[ "$WEB_ENUM" == "1" && "$NIKTO_ENABLE" == "1" ]] && have nikto; then
            echo "[+] Running nikto"
            run_with_timeout "$NIKTO_MAXTIME" nikto \
                -h "$URL" \
                -output "enum/web/nikto-$SAFE_URL.txt" || true
        elif [[ "$WEB_ENUM" == "1" && "$NIKTO_ENABLE" != "1" ]]; then
            echo "[i] Skipping Nikto in standard mode. Set NIKTO_ENABLE=1 or RECON_DEEP=1 to enable it."
        fi

        if [ "$SCHEME" = "https" ] && have openssl; then
            echo "[+] Running HTTPS/TLS checks"
            echo | run_with_timeout "$WEB_PROBE_MAXTIME" openssl \
                s_client -connect "$IP:$PORT" -servername "$HOST" 2>/dev/null \
                | openssl x509 -noout -text > "enum/web/cert-$SAFE_URL.txt" || true

            run_with_timeout "$NMAP_MAXTIME" nmap \
                --script ssl-cert,ssl-enum-ciphers -Pn -p "$PORT" "$IP" \
                -oN "enum/web/nmap-ssl-$SAFE_URL.txt" || true
        fi

        # Broad Nuclei/DAST assessment runs once after hostname discovery below.
    done < enum/web/live-web-urls.txt
else
    echo "[-] No web services detected."
    record_result skipped 0 "No live web services"
fi

echo
echo "=============================="
echo "[+] 6. DNS enumeration"
echo "=============================="
show_progress 6 "DNS enumeration"

if ports_lines | grep -q '^53$' || grep -Eq '^53/udp[[:space:]]+open([[:space:]]|$)' scans/udp-top100.txt; then
    if have dig; then
        run_with_timeout "$SERVICE_ENUM_MAXTIME" dig @"$IP" "$HOST" A | tee enum/dns/dig-a.txt || true
        run_with_timeout "$SERVICE_ENUM_MAXTIME" dig @"$IP" "$HOST" ANY | tee enum/dns/dig-any.txt || true
        run_with_timeout "$SERVICE_ENUM_MAXTIME" dig @"$IP" "$HOST" NS | tee enum/dns/dig-ns.txt || true
        run_with_timeout "$SERVICE_ENUM_MAXTIME" dig @"$IP" "$HOST" SOA | tee enum/dns/dig-soa.txt || true
        run_with_timeout "$SERVICE_ENUM_MAXTIME" dig @"$IP" "$HOST" MX | tee enum/dns/dig-mx.txt || true
        run_with_timeout "$SERVICE_ENUM_MAXTIME" dig @"$IP" "$HOST" TXT | tee enum/dns/dig-txt.txt || true
        run_with_timeout "$SERVICE_ENUM_MAXTIME" dig axfr @"$IP" "$HOST" | tee enum/dns/axfr.txt || true
    fi

    if have dnsrecon; then
        # Keep DNSRecon pinned to the supplied resolver. The all-types mode can
        # follow advertised NS addresses and leave the explicitly scoped target.
        run_with_timeout "$SERVICE_ENUM_MAXTIME" dnsrecon -d "$HOST" -n "$IP" -t srv \
            | tee enum/dns/dnsrecon.txt || true
    fi

    if have gobuster; then
        if [ -n "$DNS_WORDLIST" ]; then
            if gobuster dns --help 2>&1 | grep -q -- '--domain'; then
                run_with_timeout 900 gobuster dns \
                    --domain "$HOST" \
                    --resolver "$IP" \
                    --wordlist "$DNS_WORDLIST" \
                    --output enum/dns/gobuster-dns.txt || true
            else
                run_with_timeout 900 gobuster dns \
                    -d "$HOST" \
                    -r "$IP" \
                    -w "$DNS_WORDLIST" \
                    -o enum/dns/gobuster-dns.txt || true
            fi
        else
            echo "[!] Skipping gobuster DNS: no DNS wordlist found."
        fi
    fi

    if have ffuf; then
        if [ -n "$DNS_WORDLIST" ]; then
            echo "[+] Running ffuf DNS/vhost discovery against http://$IP/"
            run_with_timeout "$FFUF_MAXTIME" ffuf \
                -noninteractive \
                -ac \
                -t "$FFUF_THREADS" \
                -rate "$FFUF_RATE" \
                -maxtime "$FFUF_MAXTIME" \
                -w "$DNS_WORDLIST" \
                -u "http://$IP/" \
                -H "Host: FUZZ.$HOST" \
                -of json \
                -o enum/dns/ffuf-vhosts-ip.json || true
        else
            echo "[!] Skipping ffuf DNS/vhost discovery: no DNS wordlist found."
        fi
    fi

    extract_dns_hostnames
    probe_discovered_hostnames

    echo "[+] Discovered hostnames:"
    cat enum/dns/discovered-hostnames.txt || true
    echo "[+] Hosts additions candidate file: enum/dns/hosts-additions.txt"
else
    echo "[-] DNS port not detected."
    record_result skipped 0 "DNS port not detected"
    extract_dns_hostnames
    probe_discovered_hostnames
fi

echo
echo "=============================="
echo "[+] 7. Web application assessment"
echo "=============================="
show_progress 7 "Web application assessment"

if [[ "$TARGET_IS_AD" == "1" && "$WEB_ASSESS" == "1" && "$NUCLEI_ENABLE" == "1" ]] && \
   { [[ -s enum/web/live-web-urls.txt ]] || [[ -s enum/web/discovered-host-web-urls.txt ]]; }; then
    echo "[i] Deferring broad web assessment until Windows/AD service enumeration is complete."
else
    run_web_assessment
fi

echo
echo "=============================="
echo "[+] 8. SMB enumeration"
echo "=============================="
show_progress 8 "SMB enumeration"

SMB_PORTS="$(service_ports '^(139|445)$' '^(microsoft-ds|netbios-ssn|smb)$')"
if [[ -n "$SMB_PORTS" ]]; then
    # Fast modern fingerprinting first. These clients use 445 implicitly, so
    # do not run them against a NetBIOS-only or unusual-port SMB endpoint.
    if ports_lines | grep -q '^445$'; then
        if have netexec; then
            run_with_timeout "$SERVICE_ENUM_MAXTIME" netexec smb "$IP" \
                | tee enum/smb/netexec-smb.txt || true
        elif have crackmapexec; then
            run_with_timeout "$SERVICE_ENUM_MAXTIME" crackmapexec smb "$IP" \
                | tee enum/smb/cme-smb.txt || true
        fi
    fi

    for SMB_PORT in ${SMB_PORTS//,/ }; do
        if have smbclient; then
            run_with_timeout "$SERVICE_ENUM_MAXTIME" smbclient -L "\\\\$IP" -N -p "$SMB_PORT" \
                | tee "enum/smb/smbclient-null-$SMB_PORT.txt" || true
        else
            record_result skipped 0 "smbclient unavailable"
        fi
        SMB_SCRIPT_ARGS=()
        # smbport means direct SMB transport; retain NetBIOS semantics on 139.
        if [[ "$SMB_PORT" != 139 ]]; then SMB_SCRIPT_ARGS=(--script-args "smbport=$SMB_PORT"); fi
        run_with_timeout "$NMAP_MAXTIME" nmap -sV \
            --script smb-os-discovery,smb-enum-shares,smb-enum-users,smb-enum-groups,smb-enum-services,smb-enum-sessions,smb-security-mode,smb2-security-mode,smb2-time \
            "${SMB_SCRIPT_ARGS[@]}" -Pn -p "$SMB_PORT" "$IP" \
            -oN "enum/smb/nmap-smb-$SMB_PORT.txt" -oX "enum/smb/nmap-smb-$SMB_PORT.xml" || true
    done

    # enum4linux supports both direct SMB and NetBIOS transport.
    if ports_lines | grep -Eq '^(139|445)$'; then
        if have enum4linux-ng; then
            run_with_timeout "$SERVICE_ENUM_MAXTIME" enum4linux-ng "$IP" -oA enum/smb/enum4linux-ng || true
        elif [[ "$RECON_DEEP" == "1" ]] && have enum4linux; then
            run_with_timeout "$SERVICE_ENUM_MAXTIME" enum4linux -a "$IP" \
                | tee enum/smb/enum4linux.txt || true
        elif have enum4linux; then
            echo "[i] Skipping legacy enum4linux in standard mode. Enable with RECON_DEEP=1."
            record_result skipped 0 "Legacy enum4linux disabled in standard mode"
        fi
    else
        record_result skipped 0 "enum4linux skipped on nonstandard SMB ports; explicit-port evidence collected"
    fi

    # These clients default to 445. NetBIOS 139 alone does not authorize that
    # implicit endpoint; smbclient and NSE above already use the discovered port.
    if ports_lines | grep -q '^445$'; then
        if have smbmap; then
            run_with_timeout "$SERVICE_ENUM_MAXTIME" smbmap -H "$IP" \
                | tee enum/smb/smbmap-null.txt || true
        fi
    else
        record_result skipped 0 "Port 445 SMB clients skipped: 445 not discovered; explicit-port SMB evidence collected"
    fi
else
    echo "[-] SMB ports not detected."
    record_result skipped 0 "SMB ports not detected"
fi

echo
echo "=============================="
echo "[+] 8.5 MQTT enumeration"
echo "=============================="

if ports_lines | grep -q '^1883$'; then
    if have mosquitto_sub; then
        echo "[+] Collecting bounded, read-only MQTT system topics."
        run_bounded_listener "$MQTT_ENUM_MAXTIME" mosquitto_sub \
            -h "$IP" -p 1883 -t '$SYS/#' -v \
            | tee enum/mqtt/sys-topics.txt || true
        if [ "$MQTT_ALL_TOPICS" = "1" ]; then
            echo "[+] Deep mode: collecting bounded, read-only MQTT application topics."
            run_bounded_listener "$MQTT_ENUM_MAXTIME" mosquitto_sub \
                -h "$IP" -p 1883 -t '#' -v \
                | tee enum/mqtt/all-topics.txt || true
        fi
    else
        echo "[i] MQTT detected. Install mosquitto-clients for bounded topic collection."
        echo "[i] Existing Nmap mqtt-subscribe evidence remains available in scans/."
    fi
else
    echo "[-] MQTT port 1883 not detected."
fi

echo
echo "=============================="
echo "[+] 9. FTP enumeration"
echo "=============================="
show_progress 9 "FTP enumeration"

if ports_lines | grep -q '^21$'; then
    run_with_timeout "$NMAP_MAXTIME" nmap \
        --script ftp-anon,ftp-syst,ftp-bounce -Pn -p21 "$IP" \
        -oN enum/ftp/nmap-ftp.txt || true

    if have ftp; then
        printf "anonymous\nanonymous@\nbye\n" \
            | run_with_timeout "$SERVICE_ENUM_MAXTIME" ftp -inv "$IP" 2>&1 \
            | tee enum/ftp/ftp-anonymous-check.txt || true
    fi
else
    echo "[-] FTP port not detected."
    record_result skipped 0 "FTP port not detected"
fi

echo
echo "=============================="
echo "[+] 10. SSH enumeration"
echo "=============================="
show_progress 10 "SSH enumeration"

if ports_lines | grep -q '^22$'; then
    run_with_timeout "$NMAP_MAXTIME" nmap \
        --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -Pn -p22 "$IP" \
        -oN enum/ssh/nmap-ssh.txt || true

    if have nc; then
        run_with_timeout 30 nc -nv "$IP" 22 2>&1 | tee enum/ssh/ssh-banner.txt || true
    fi
else
    echo "[-] SSH port not detected."
    record_result skipped 0 "SSH port not detected"
fi

echo
echo "=============================="
echo "[+] 11. NFS enumeration"
echo "=============================="
show_progress 11 "NFS enumeration"

if ports_lines | grep -Eq '^(111|2049)$'; then
    NFS_PORTS="$(ports_lines | grep -E '^(111|2049)$' | paste -sd, -)"

    if have showmount; then
        run_with_timeout "$SERVICE_ENUM_MAXTIME" showmount -e "$IP" \
            | tee enum/nfs/showmount.txt || true
    fi

    run_with_timeout "$NMAP_MAXTIME" nmap \
        --script nfs-ls,nfs-showmount,nfs-statfs -Pn -p "$NFS_PORTS" "$IP" \
        -oN enum/nfs/nmap-nfs.txt || true
else
    echo "[-] NFS/RPCBind ports not detected."
    record_result skipped 0 "NFS/RPCBind ports not detected"
fi

echo
echo "=============================="
echo "[+] 12. RPC enumeration"
echo "=============================="
show_progress 12 "RPC enumeration"

RPC_ENUM_FOUND=0
if ports_lines | grep -q '^111$'; then
    RPC_ENUM_FOUND=1
    if have rpcinfo; then
        run_with_timeout "$SERVICE_ENUM_MAXTIME" rpcinfo -p "$IP" \
            | tee enum/rpc/rpcinfo.txt || true
    fi

    run_with_timeout "$NMAP_MAXTIME" nmap \
        --script rpc-grind,rpcinfo -Pn -p111 "$IP" -oN enum/rpc/nmap-rpc.txt || true
fi

if ports_lines | grep -Eq '^(135|593)$'; then
    RPC_ENUM_FOUND=1
    MSRPC_PORTS="$(ports_lines | grep -E '^(135|593)$' | paste -sd, -)"

    if have rpcclient; then
        run_with_timeout "$SERVICE_ENUM_MAXTIME" rpcclient -U '' -N "$IP" -c srvinfo \
            | tee enum/rpc/rpcclient-null-srvinfo.txt || true
    fi

    if have impacket-rpcdump; then
        run_with_timeout "$SERVICE_ENUM_MAXTIME" impacket-rpcdump -target-ip "$IP" "@$IP" \
            | tee enum/rpc/impacket-rpcdump.txt || true
    elif have rpcdump.py; then
        run_with_timeout "$SERVICE_ENUM_MAXTIME" rpcdump.py -target-ip "$IP" "@$IP" \
            | tee enum/rpc/impacket-rpcdump.txt || true
    fi

    run_with_timeout "$NMAP_MAXTIME" nmap \
        --script msrpc-enum -Pn -p "$MSRPC_PORTS" "$IP" -oN enum/rpc/nmap-msrpc.txt || true
fi

if [ "$RPC_ENUM_FOUND" = "0" ]; then
    echo "[-] RPCBind/MSRPC ports not detected."
    record_result skipped 0 "RPCBind/MSRPC ports not detected"
fi

echo
echo "=============================="
echo "[+] 13. SNMP enumeration"
echo "=============================="
show_progress 13 "SNMP enumeration"

if awk '$1 == "161/udp" && $2 == "open" { found=1 } END { exit !found }' scans/udp-top100.txt; then
    if have onesixtyone; then
        if [ -n "$SNMP_WORDLIST" ]; then
            run_with_timeout "$SERVICE_ENUM_MAXTIME" onesixtyone -c "$SNMP_WORDLIST" "$IP" \
                | tee enum/snmp/onesixtyone.txt || true
        else
            echo "[!] Skipping onesixtyone: no SNMP community wordlist found."
        fi
    fi

    if have snmpwalk; then
        run_with_timeout "$SERVICE_ENUM_MAXTIME" snmpwalk -v2c -c public "$IP" \
            | tee enum/snmp/snmpwalk-public.txt || true
    fi

    run_with_timeout "$NMAP_MAXTIME" nmap \
        -sU --script snmp-info,snmp-interfaces,snmp-processes,snmp-sysdescr \
        -Pn -p161 "$IP" -oN enum/snmp/nmap-snmp.txt || true
else
    echo "[-] SNMP UDP/161 not detected in top UDP scan."
    record_result skipped 0 "SNMP UDP/161 not detected"
fi

echo
echo "=============================="
echo "[+] 14. LDAP enumeration"
echo "=============================="
show_progress 14 "LDAP enumeration"

LDAP_PORTS="$(service_ports '^(389|636|3268|3269)$' '^(ssl/)?ldaps?$')"
if [[ -n "$LDAP_PORTS" ]]; then

    run_with_timeout "$NMAP_MAXTIME" nmap \
        -sV --script ldap-rootdse -Pn -p "$LDAP_PORTS" "$IP" \
        -oN enum/ldap/nmap-ldap.txt -oX enum/ldap/nmap-ldap.xml || true

    # A separate invocation has no credential registry from other NSE scripts.
    # Only user account names are requested, with a small explicit object cap.
    run_with_timeout "$NMAP_MAXTIME" nmap \
        -sV --script ldap-search \
        --script-args ldap.maxobjects=20,ldap.qfilter=users,ldap.attrib=sAMAccountName \
        -Pn -p "$LDAP_PORTS" "$IP" \
        -oN enum/ldap/nmap-ldap-search.txt -oX enum/ldap/nmap-ldap-search.xml || true

    if have ldapsearch; then
        for LDAP_PORT in ${LDAP_PORTS//,/ }; do
            LDAP_SCHEME=ldap
            if service_uses_tls "$LDAP_PORT"; then LDAP_SCHEME=ldaps; fi
            LDAP_URI="$LDAP_SCHEME://$IP:$LDAP_PORT"
            printf '# Target: %s\n# Anonymous rootDSE metadata only; not directory-object access evidence.\n' "$LDAP_URI" > "enum/ldap/namingcontexts-$LDAP_PORT.txt"
            LDAPTLS_REQCERT=never run_with_timeout "$SERVICE_ENUM_MAXTIME" ldapsearch \
                -x -H "$LDAP_URI" -o nettimeout=10 -l 20 -s base -b '' '(objectClass=*)' \
                namingContexts defaultNamingContext rootDomainNamingContext dnsHostName supportedLDAPVersion \
                domainFunctionality forestFunctionality \
                | tee -a "enum/ldap/namingcontexts-$LDAP_PORT.txt" || true
        done
    else
        record_result skipped 0 "ldapsearch unavailable; Nmap rootDSE evidence only"
    fi
else
    echo "[-] LDAP ports not detected."
    record_result skipped 0 "LDAP ports not detected"
fi

echo
echo "=============================="
echo "[+] 15. Kerberos enumeration"
echo "=============================="
show_progress 15 "Kerberos enumeration"

KERBEROS_PORTS="$(service_ports '^88$' '^(kerberos|kerberos-sec|kerberos5)$')"
if [[ -n "$KERBEROS_PORTS" ]]; then
    run_with_timeout "$NMAP_MAXTIME" nmap \
        -sV -Pn -p "$KERBEROS_PORTS" "$IP" \
        -oN enum/kerberos/nmap-kerberos.txt -oX enum/kerberos/nmap-kerberos.xml || true
    if [ -n "$KERBEROS_USERDB" ] && [ -f "$KERBEROS_USERDB" ] && [ -n "$KERBEROS_REALM" ]; then
        echo "[+] Running explicitly enabled Kerberos username enumeration."
        run_with_timeout "$NMAP_MAXTIME" nmap \
            --script krb5-enum-users \
            --script-args "krb5-enum-users.realm=$KERBEROS_REALM,userdb=$KERBEROS_USERDB" \
            -Pn -p "$KERBEROS_PORTS" "$IP" -oN enum/kerberos/nmap-kerberos-users.txt || true
    else
        echo "[i] Kerberos detected; intrusive username enumeration is disabled by default."
        echo "[i] To enable it, set KERBEROS_REALM and KERBEROS_USERDB=/path/to/users.txt."
        record_result skipped 0 "Kerberos username guessing requires explicit realm and user list"
    fi
else
    echo "[-] Kerberos port not detected."
    record_result skipped 0 "Kerberos port not detected"
fi

echo
echo "=============================="
echo "[+] 16. WinRM enumeration"
echo "=============================="
show_progress 16 "WinRM enumeration"

WINRM_PORTS="$(service_ports '^(5985|5986)$' '^(ssl/)?(winrm|wsman)$' 'microsoft[ -]httpapi')"
if [[ -n "$WINRM_PORTS" ]]; then

    # Microsoft HTTPAPI on another port is a candidate, not proof of WinRM.
    # /wsman NTLM metadata is useful without authenticating or invoking methods.
    run_with_timeout "$NMAP_MAXTIME" nmap \
        -sV --script +http-ntlm-info --script-args http-ntlm-info.root=/wsman \
        -Pn -p "$WINRM_PORTS" "$IP" \
        -oN enum/winrm/nmap-winrm.txt -oX enum/winrm/nmap-winrm.xml || true

    if ports_lines | grep -Eq '^(5985|5986)$'; then
        if have netexec; then
            run_with_timeout "$SERVICE_ENUM_MAXTIME" netexec winrm "$IP" \
                | tee enum/winrm/netexec-winrm.txt || true
        elif have crackmapexec; then
            run_with_timeout "$SERVICE_ENUM_MAXTIME" crackmapexec winrm "$IP" \
                | tee enum/winrm/cme-winrm.txt || true
        fi
    else
        record_result skipped 0 "Default-port WinRM clients skipped; HTTPAPI candidate metadata collected"
    fi
else
    echo "[-] WinRM ports not detected."
    record_result skipped 0 "WinRM ports not detected"
fi

if [[ "$TARGET_IS_AD" == "1" && "$WEB_ASSESS_RAN" == "0" ]]; then
    echo
    echo "[+] Deferred web application assessment"
    run_web_assessment
fi

echo
echo "=============================="
echo "[+] 17. RDP enumeration"
echo "=============================="
show_progress 17 "RDP enumeration"

RDP_PORTS="$(service_ports '^3389$' '^(ssl/)?(ms-wbt-server|rdp)$')"
if [[ -n "$RDP_PORTS" ]]; then
    run_with_timeout "$NMAP_MAXTIME" nmap -sV -Pn -p "$RDP_PORTS" "$IP" \
        --script rdp-ntlm-info,rdp-enum-encryption \
        -oN enum/rdp/nmap-rdp.txt -oX enum/rdp/nmap-rdp.xml || true
else
    record_result skipped 0 "RDP service not detected"
fi

echo
echo "=============================="
echo "[+] 18. MSSQL enumeration"
echo "=============================="
show_progress 18 "MSSQL enumeration"

MSSQL_PORTS="$(service_ports '^1433$' '^(ms-sql-s|mssql)$')"
if [[ -n "$MSSQL_PORTS" ]]; then
    # NSE otherwise may follow SQL Browser instances to ports outside this scan.
    run_with_timeout "$NMAP_MAXTIME" nmap -sV -Pn -p "$MSSQL_PORTS" "$IP" \
        --script ms-sql-info,ms-sql-ntlm-info --script-args mssql.scanned-ports-only=true \
        -oN enum/mssql/nmap-mssql.txt -oX enum/mssql/nmap-mssql.xml || true
else
    record_result skipped 0 "MSSQL service not detected"
fi

echo
echo "=============================="
echo "[+] 19. Generate port summary"
echo "=============================="
show_progress 19 "Generate port summary"

{
    echo "# Port Summary"
    echo
    echo "| Port | Service | Version | Notes |"
    echo "|---:|---|---|---|"
    awk '$1 ~ /^[0-9]+\/tcp$/ && $2 == "open" {
        port=$1
        sub("/tcp", "", port)
        service=$3
        version=""
        for (i=4; i<=NF; i++) version=version $i " "
        gsub(/[[:space:]]+$/, "", version)
        printf("| %s | %s | %s | |\n", port, service, version)
    }' scans/tcp-services.txt
} | tee scans/port-summary.md

echo
echo "========================================="
echo "[+] 20. Optional vulnerability Nmap scan"
echo "========================================="
show_progress 20 "Nmap vulnerability scan"

if [[ "$VULN_SCAN" == "1" && -n "$PORTS" ]]; then
    echo "[+] This scan can be slow/noisy. Treat results as hints."
    echo "[+] Service detection is enabled so version-dependent scripts such as Vulners can run."
    # NSE does not reuse version/CPE information from the earlier invocation.
    run_with_timeout "$NMAP_MAXTIME" nmap \
        -sV --script "vuln and not broadcast" -Pn -p "$PORTS" "$IP" \
        -oN scans/tcp-vuln.txt -oX scans/tcp-vuln.xml || true
elif [[ "$VULN_SCAN" == "1" ]]; then
    record_result skipped 0 "No confirmed open TCP ports"
    : > scans/tcp-vuln.txt
else
    echo "[i] Skipping broad vulnerability NSE in standard mode. Set VULN_SCAN=1 or RECON_DEEP=1 to enable it."
    record_result skipped 0 "Broad vulnerability NSE disabled in standard mode"
    : > scans/tcp-vuln.txt
fi

echo
echo "=============================="
echo "[+] 21. Interesting grep"
echo "=============================="
show_progress 21 "Interesting-result extraction"

grep -RniIE \
    --exclude="interesting-grep.txt" \
    --exclude="summary.md" \
    --exclude="recon-console.log" \
    --exclude="http.templates.txt" \
    --exclude="targets.txt" \
    --exclude="priority-vhosts.txt" \
    --exclude-dir="assessments" \
    --exclude="*.zip" \
    --exclude="*.map" \
    --exclude="ffuf-vhosts-*.json" \
    --exclude="*tailwind*" \
    --exclude="*polyfills*" \
    --exclude="*webpack*" \
    --exclude="package-lock.json" \
    "admin|login|dashboard|api|jwt|token|auth|credentials?|password|passwd|ssh|private key|id_rsa|backup|bak|old|debug|dev|test|staging|pac4j|jwe|jws|jwks|principal|root|secret|\bkey\b" \
    scans enum 2>/dev/null \
    | truncate_lines \
    | tee enum/interesting-grep.txt || true

echo
echo "=============================="
echo "[+] 22. Generate recon summary"
echo "=============================="
show_progress 22 "Generate recon summary"

LATEST_WEB_REPORT="$(find enum/web/assessments -mindepth 2 -maxdepth 2 -name report.json -type f 2>/dev/null | sort | tail -1 || true)"

{
    echo "# Recon Summary - $BOX"
    echo
    echo "## Target"
    echo
    echo "- IP: $IP"
    echo "- Hostname: $HOST"
    echo "- Started: $START_TIME"
    echo "- Finished: $(date)"
    echo
    echo "## Target Profile"
    echo
    cat scans/target-profile.txt 2>/dev/null || true
    echo
    echo "## Open TCP Ports"
    echo
    if [[ -z "$PORTS" ]]; then echo "No open TCP ports were discovered; see run-status.json for discovery completeness."; fi
    cat scans/port-summary.md 2>/dev/null || true
    echo
    echo "## Service Scan"
    echo
    grep -E '^[0-9]+/tcp\s+open' scans/tcp-services.txt 2>/dev/null || true
    echo
    echo "## Open UDP Ports"
    echo
    grep -E '^[0-9]+/udp\s+open[[:space:]]' scans/udp-top100.txt 2>/dev/null || true
    echo
    echo "## Windows / AD Evidence"
    echo
    cat enum/smb/netexec-smb.txt enum/smb/cme-smb.txt enum/ad/clock-skew.txt enum/ad/ntp-query.txt 2>/dev/null || true
    grep -E 'Message signing enabled and required|Domain (Name|Sid):|Null Auth:' \
        enum/smb/*.txt 2>/dev/null | truncate_lines 80 || true
    echo
    echo "## LDAP Naming Contexts"
    echo
    grep -Ei '^(dnsHostName|rootDomainNamingContext|defaultNamingContext|namingContexts|domainFunctionality|forestFunctionality):' \
        enum/ldap/namingcontexts-*.txt enum/ldap/rootdse.txt 2>/dev/null || true
    echo
    echo "## MQTT Evidence"
    echo
    grep -hE 'mqtt-subscribe:|\$SYS/|mqttui-' \
        scans/tcp-services.txt scans/tcp-aggressive.txt scans/tcp-default-safe-scripts.txt 2>/dev/null \
        | truncate_lines 100 || true
    cat enum/mqtt/sys-topics.txt enum/mqtt/all-topics.txt 2>/dev/null | truncate_lines 100 || true
    echo
    echo "## Live Web URLs"
    echo
    cat enum/web/live-web-urls.txt 2>/dev/null || true
    echo
    echo "## Vhost Base Domains"
    echo
    cat enum/dns/vhost-base-domains.txt 2>/dev/null || true
    echo
    echo "## Discovered DNS Hostnames"
    echo
    cat enum/dns/discovered-hostnames.txt 2>/dev/null || true
    echo
    echo "## Discovered Host Web Probe"
    echo
    cat enum/web/discovered-host-web-probe.txt 2>/dev/null || true
    echo
    echo "## HTTPX Web Services"
    echo
    cat enum/web/httpx-web-services.txt 2>/dev/null || true
    echo
    echo "## Web Assessment Status"
    echo
    if [ -n "$LATEST_WEB_REPORT" ]; then
        echo "- Report: $LATEST_WEB_REPORT"
        if have jq; then
            jq -r '"- Status: \(.status // \"unknown\")\n- Findings: \((.findings // []) | length)\n- Diagnostics: \((.diagnostics // []) | join(\"; \"))"' \
                "$LATEST_WEB_REPORT" 2>/dev/null || true
        else
            sed -n '1,80p' "$LATEST_WEB_REPORT"
        fi
    else
        echo "- Not run (broad Nuclei assessment is deep/opt-in)."
    fi
    echo
    echo "## Curl Web Probe"
    echo
    cat enum/web/curl-web-probe.txt 2>/dev/null || true
    echo
    echo "## Web Fingerprinting"
    echo
    cat enum/web/whatweb-*.txt 2>/dev/null || true
    echo
    echo "## Detected Web Technology Profiles"
    echo
    for f in enum/web/technology-profile-*.txt; do
        [ -f "$f" ] || continue
        echo "### $f"
        cat "$f"
        echo
    done
    echo
    echo "## Web Wordlist Plans"
    echo
    for f in enum/web/wordlists-*.txt; do
        [ -f "$f" ] || continue
        echo "### $f"
        cat "$f"
        echo
    done
    echo
    echo "## Interesting Web Headers"
    echo
    grep -RniIE \
        --exclude-dir="assessments" \
        --exclude="http.templates.txt" \
        --exclude="targets.txt" \
        --exclude="*.map" \
        --exclude="*tailwind*" \
        --exclude="*polyfills*" \
        --exclude="*webpack*" \
        "server:|x-powered-by:|set-cookie:|location:|authorization|jwt|token|pac4j|spring|jetty|tomcat|nginx|apache" \
        enum/web/ 2>/dev/null \
        | truncate_lines || true
    echo
    echo "## Ferox Results"
    grep -hE "^[0-9]{3}" enum/web/ferox-*.txt 2>/dev/null || true
    echo
    echo "## FFUF Vhost Results"
    if have jq; then
        for f in enum/web/ffuf-vhosts-*.json; do
            [ -f "$f" ] && jq -r '.results[]? | "\(.status) \(.length) \(.words) \(.host) \(.url)"' "$f" 2>/dev/null || true
        done
    else
        cat enum/web/ffuf-vhosts-*.json 2>/dev/null || true
    fi
    echo
    echo "## FFUF Content Results"
    if have jq; then
        for f in enum/web/ffuf-content-*.json; do
            [ -f "$f" ] && jq -r '.results[]? | "\(.status) \(.length) \(.words) \(.url)"' "$f" 2>/dev/null || true
        done
    else
        cat enum/web/ffuf-content-*.json 2>/dev/null || true
    fi
    echo
    echo "## Interesting Grep Results"
    cat enum/interesting-grep.txt 2>/dev/null || true
    echo
    echo "## Files To Review"
    find scans enum -type f -size +0c | sort
} > summary.md

echo
echo "========================================"
echo "[+] 23. Online OSV/NVD vulnerability intel"
echo "========================================"
write_run_status completed
show_progress 23 "Online OSV/NVD vulnerability intelligence"

run_online_vuln_analysis
write_run_status completed
{
    echo
    echo "## Run coverage"
    echo
    if grep -q $'\terror\t' run-stages.tsv; then
        echo "Collection is incomplete: one or more commands failed or timed out. See run-status.json."
    else
        echo "Requested stages finished. Review skipped coverage and tool limits in run-status.json."
    fi
    echo "Start with overview.md for the prioritized evidence and next actions."
} >> summary.md

echo
echo "[+] Recon complete."
echo "[+] Main files to review:"
echo "    summary.md"
echo "    overview.md"
echo "    overview.json"
echo "    run-status.json"
echo "    recon-analysis.md"
echo "    scans/tcp-full.txt"
echo "    scans/tcp-services.txt"
echo "    scans/tcp-aggressive.txt"
echo "    scans/tcp-vuln.txt"
echo "    scans/udp-top100.txt"
echo "    scans/port-summary.md"
echo "    enum/web/live-web-urls.txt"
echo "    enum/web/curl-web-probe.txt"
echo "    enum/web/technology-profile-*.txt"
echo "    enum/dns/discovered-hostnames.txt"
echo "    enum/dns/hosts-additions.txt"
echo "    enum/interesting-grep.txt"
echo "    enum/"
echo "    notes.md"
echo "    writeup.md"

echo
echo "=============================="
echo "[+] 24. Creating recon archive"
echo "=============================="
show_progress 24 "Create recon archive"

if ! run_with_timeout "$ARCHIVE_MAXTIME" ./zip-recon.sh; then
    echo "[!] WARNING: Recon archive creation failed."
    # Refresh the short overview with the final failure without repeating
    # online lookups. Its coverage must agree with run-status.json.
    write_run_status completed
    ONLINE_VULN_CHECK=0 run_online_vuln_analysis
fi

END_TIME="$(date)"
END_EPOCH="$(date +%s)"
if grep -q $'\terror\t' run-stages.tsv; then
    echo "[!] Run incomplete | elapsed $(format_elapsed "$((END_EPOCH - START_EPOCH))") | review run-status.json and overview.md"
else
    echo "[+] Progress: 100% | elapsed $(format_elapsed "$((END_EPOCH - START_EPOCH))") | requested stages finished; review overview.md"
fi
echo "[+] Recon finished at: $END_TIME"
EOF

chmod +x recon.sh

cat > privesc-linux.md <<'EOF'
# Linux Privilege Escalation Checklist

## Context

```bash
whoami
id
hostname
pwd
uname -a
cat /etc/os-release
```

## Sudo

```bash
sudo -l
```

## Users and Groups

```bash
cat /etc/passwd
cat /etc/group
ls -la /home
find /home -type f -readable 2>/dev/null
```

## SUID / SGID

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
```

## Capabilities

```bash
getcap -r / 2>/dev/null
```

## Writable Paths

```bash
find / -writable -type d 2>/dev/null
find / -writable -type f 2>/dev/null
```

## Processes and Services

```bash
ps aux
ss -tulpn
systemctl list-units --type=service --state=running
```

## Cron

```bash
cat /etc/crontab
ls -la /etc/cron*
crontab -l 2>/dev/null
```

## Interesting Files

```bash
find / -name "*.conf" -readable 2>/dev/null
find / -name "*.bak" -readable 2>/dev/null
find / -name "*.old" -readable 2>/dev/null
find / -name "*.zip" -readable 2>/dev/null
find / -name "*password*" -readable 2>/dev/null
find / -name "*backup*" -readable 2>/dev/null
```

## Shell Stabilization

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
stty rows 40 columns 120
```

EOF

cat > README.md <<EOF

# $BOX HTB Workspace

## Target

* Box: $BOX
* IP: $IP
* Hostname: $HOST

## Offline Analysis and Inspection

Install ScopeLens 0.2+ in your active Python environment, then prepare an existing
workspace once with \`scopelens prepare .\`. New workspaces are prepared
automatically when ScopeLens is available to the initializer.

\`\`\`bash
./inspect.sh
./analyze.sh
# After the first report, compare the next snapshot:
./analyze.sh --baseline latest
\`\`\`

Review \`scope.json\` before analysis. User scope exclusions and notes are
preserved. Reports go into separate directories under \`reports/\`; open the
printed \`report.html\` path to inspect the results. See \`ANALYSIS.md\` for
the full local review workflow. These commands analyze existing evidence.

## Recommended Launch Flow

\`\`\`bash
cd $BASE_DIR
./update-hosts.sh
./recon.sh
less overview.md
less summary.md
less recon-analysis.md
\`\`\`

## Main Files

* .target.env - machine-local config
* summary.md - generated recon summary
* overview.md and overview.json - short ranked attack paths and coverage gaps
* recon-analysis.md - evidence-driven prioritized next steps
* notes.md - working notes
* writeup.md - final report/writeup
* recon.sh - automated first-stage recon
* web-assess.sh - bounded HTTP template and query DAST checks, plus OWASP review checklist
* enum/web/assessments/ - independent web assessment runs, findings and stage logs
* search-recon.sh - search collected recon and optionally copy matched files
* file-hunt.sh - find readable files by name pattern and copy matches to loot
* update-hosts.sh - update /etc/hosts for this box
* zip-recon.sh - archive recon results
* privesc-linux.md - local Linux privilege escalation checklist
* recon-console.log - full terminal output from recon
* run-status.json and run-stages.tsv - current collection status and command outcomes
* runs/ - recoverable generated evidence from previous runs
* scans/ - Nmap outputs
* enum/ - service-specific enumeration outputs

## Windows Target Evidence

Run this collector from Kali for Windows targets as well. SMB, LDAP/LDAPS,
Kerberos, WinRM, RDP, and MSSQL checks save text and XML beneath their matching
\`enum/\` directories. Detected services on unusual TCP ports are included.
LDAP account-name searches are anonymous and limited to 20 objects; rootDSE
metadata alone does not prove anonymous directory access. Kerberos username
guessing is skipped unless both KERBEROS_REALM and KERBEROS_USERDB are supplied.
WinRM management fingerprints are kept out of automatic web application
testing. Every command retains the configured timeout.

## Useful Review Commands

\`\`\`bash
cat scans/open-tcp-ports.txt
cat scans/port-summary.md
cat enum/web/live-web-urls.txt
cat enum/web/technology-profile-*.txt
cat enum/dns/vhost-base-domains.txt
cat enum/dns/discovered-hostnames.txt
cat enum/dns/hosts-additions.txt
cat enum/web/curl-web-probe.txt
cat enum/interesting-grep.txt
less summary.md
./search-recon.sh 'password|token|backup' --copy
./file-hunt.sh 'config.php' .
\`\`\`

## Runtime Safety Knobs

Default recon is conservative and keeps broad Nuclei, Nikto, legacy enum4linux,
and the Nmap vulnerability category disabled. Deep mode restores those checks.
Every new run archives previous generated evidence in runs/.
Windows/AD detection is automatic and additive: it records the target profile,
LDAP rootDSE, RPC, SMB, and clock-skew evidence without changing local time.
Kerberos username enumeration runs only when a realm and user list are supplied.

\`\`\`bash
# Fast default recon
./recon.sh

# Disable all heavy web fuzzing
WEB_ENUM=0 WEB_ASSESS=0 ./recon.sh

# Run web assessment independently; preview targets without network access
./web-assess.sh --dry-run
./web-assess.sh --insecure --oast

# Run ferox but without extension multiplication or collect-backups
FEROX_EXTENSIONS=0 FEROX_COLLECT=0 ./recon.sh

# Deep mode when the quick pass is finished
RECON_DEEP=1 FEROX_EXTENSIONS=1 FEROX_COLLECT=1 FFUF_CONTENT=1 ./recon.sh
FFUF_RATE=40 FFUF_THREADS=10 FFUF_MAXTIME=180 ./recon.sh
FFUF_VHOST=0 ./recon.sh
VHOST_SUFFIXES=htb,vl,local,test ./recon.sh
NIKTO_MAXTIME=300 NUCLEI_MAXTIME=300 ./recon.sh
NIKTO_ENABLE=1 NUCLEI_ENABLE=1 VULN_SCAN=1 ./recon.sh
MQTT_ALL_TOPICS=1 MQTT_ENUM_MAXTIME=30 ./recon.sh
KERBEROS_REALM=EXAMPLE.HTB KERBEROS_USERDB=/path/to/users.txt ./recon.sh
NMAP_MAXTIME=600 SERVICE_ENUM_MAXTIME=180 ./recon.sh
UPDATE_SCANNER_DATA=0 ./recon.sh

# Broad scope-aware Nuclei assessment is deep/opt-in
WEB_ASSESS=1 WEB_ASSESS_MAXTIME=2100 ./recon.sh
WEB_ASSESS=0 ./recon.sh

# Online OSV/NVD enrichment runs by default; the offline report is always made
ONLINE_VULN_CHECK=0 ./recon.sh
VULN_TIMEOUT=30 MAX_VULN_RESULTS=5 ./recon.sh
VULN_ANALYZER=/path/to/analyze-recon.py ./recon.sh
\`\`\`

## Zip Recon Manually

\`\`\`bash
./zip-recon.sh
\`\`\`
EOF

echo "[+] Done."
echo "[+] Workspace created at: $BASE_DIR"
echo
echo "[+] Optional hosts update:"
echo "cd $BASE_DIR && ./update-hosts.sh"
echo
echo "[+] Next commands:"
echo "cd $BASE_DIR"
echo "./update-hosts.sh"
echo "./recon.sh"

# ScopeLens only reads collected artifacts. Keep this integration outside the
# generated collector so review never starts network collection implicitly.
echo
prepare_offline_review "$BASE_DIR" "$BOX"
