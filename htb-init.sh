#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "Usage: htb-init <box-name> <target-ip>"
    echo "Example: htb-init principal 10.129.244.220"
    exit 1
fi

BOX="$1"
IP="$2"

if [[ ! "$BOX" =~ ^[A-Za-z0-9._-]+$ ]]; then
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
    if (( octet < 0 || octet > 255 )); then
        echo "[-] Invalid IPv4 address octet: $octet"
        exit 1
    fi
done

HOST="${BOX}.htb"
BASE_ROOT="/home/zendeni/htb_labs"
BASE_DIR="$BASE_ROOT/$BOX"

echo "[+] Creating HTB workspace for $BOX"
echo "[+] Target IP: $IP"
echo "[+] Hostname: $HOST"
echo "[+] Workspace: $BASE_DIR"

mkdir -p "$BASE_DIR"/{scans,enum/{web,dns,smb,ftp,nfs,snmp,ldap,kerberos,rpc,winrm,ssh,other},loot/{copied,searches},exploits,shells,screenshots,tools}
cd "$BASE_DIR"

cat > .target.env <<EOF
BOX="$BOX"
IP="$IP"
HOST="$HOST"
# Extra vhost base domains discovered from redirects are stored during recon in:
#   enum/dns/vhost-base-domains.txt
BASE_DIR="$BASE_DIR"
EOF

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
} | sed '/^[[:space:]]*$/d' | tr '[:upper:]' '[:lower:]' | sort -u > "$hostsfile"

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

zip -r "$OUTFILE" \
    .target.env \
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

exec > >(tee -a recon-console.log) 2>&1

START_TIME="$(date)"

# Runtime safety knobs. Defaults are intentionally conservative so recon does not
# appear to hang in ffuf/ferox sections on dynamic or slow web targets.
# Override per run, for example:
#   ./recon.sh
#   WEB_ENUM=0 ./recon.sh
#   FEROX_EXTENSIONS=0 FEROX_COLLECT=0 ./recon.sh
#   RECON_DEEP=1 FEROX_EXTENSIONS=1 FEROX_COLLECT=1 FFUF_CONTENT=1 ./recon.sh
RECON_DEEP="${RECON_DEEP:-0}"
WEB_ENUM="${WEB_ENUM:-1}"
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
MAX_WEB_URLS="${MAX_WEB_URLS:-4}"
MAX_WEB_WORDLISTS="${MAX_WEB_WORDLISTS:-1}"
MAX_FFUF_WORDLISTS="${MAX_FFUF_WORDLISTS:-1}"

have() {
    command -v "$1" >/dev/null 2>&1
}

ports_lines() {
    echo "$PORTS" | tr ',' '\n'
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

record_vhost_base_domain() {
    local name="$1"

    name="$(printf '%s' "$name" | sed 's/[[:space:]]//g; s/:$//; s/^\.//; s/\.$//' | tr '[:upper:]' '[:lower:]')"
    is_hostname_candidate "$name" || return 0
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
    cut -c1-300
}

run_with_timeout() {
    local seconds="$1"
    shift

    if have timeout; then
        timeout "$seconds" "$@"
    else
        "$@"
    fi
}

append_unique_line() {
    local value="$1"
    local file="$2"

    [ -n "$value" ] || return 0
    touch "$file"
    grep -Fxq "$value" "$file" 2>/dev/null || echo "$value" >> "$file"
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
        grep -vE '^[[:space:]]*(#|$)' "$wordlist" 2>/dev/null | wc -l | tr -d ' '
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
    local scheme port lock_file base_domain safe_base output_file

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

    if [ -z "$DNS_WORDLIST" ]; then
        echo "[!] Skipping ffuf vhost discovery: no DNS wordlist found."
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
            lock_file="enum/web/.ffuf-vhost-$scheme-$port-$safe_base-$label.done"
            output_file="enum/web/ffuf-vhosts-$safe_url-$safe_base-$label.json"

            if [ -f "$lock_file" ]; then
                echo "[!] Skipping duplicate ffuf vhost scan for $scheme/$port base $base_domain wordlist $label."
                continue
            fi
            touch "$lock_file"

            echo "[+] Running bounded ffuf vhost discovery with $vhost_wordlist against base domain: $base_domain"
            run_with_timeout "$FFUF_MAXTIME" ffuf \
                -noninteractive \
                -ac \
                -t "$FFUF_THREADS" \
                -rate "$FFUF_RATE" \
                -maxtime "$FFUF_MAXTIME" \
                -w "$vhost_wordlist" \
                -u "$url/" \
                -H "Host: FUZZ.$base_domain" \
                -of json \
                -o "$output_file" || true
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
            curl -k -s -i "$url/$path" -o "enum/web/drupal-$safe_path-$safe_url.txt" || true
        done
        if have droopescan; then
            run_with_timeout 900 droopescan scan drupal -u "$url" | tee "enum/web/droopescan-$safe_url.txt" || true
        fi
        if have nuclei; then
            nuclei -u "$url" -tags drupal,cms -severity low,medium,high,critical -o "enum/web/nuclei-drupal-$safe_url.txt" || true
        fi
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
            curl -k -s -i "$url/$path" -o "enum/web/api-$safe_path-$safe_url.txt" || true
        done
    fi
}

extract_dns_hostnames() {
    local domain domain_regex tmp raw_hosts

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
        grep -RhoE "([A-Za-z0-9_-]+\.)*$domain_regex" enum/dns enum/web 2>/dev/null >> "$raw_hosts" || true
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
        | sort -u > enum/dns/discovered-hostnames.txt || true

    cp enum/dns/discovered-hostnames.txt "$tmp"
    while read -r domain; do
        [ -n "$domain" ] || continue
        grep -Fxv "$domain" "$tmp" > "$tmp.filtered" || true
        mv "$tmp.filtered" "$tmp"
    done < enum/dns/vhost-base-domains.txt
    cp "$tmp" enum/dns/discovered-subdomains.txt

    while read -r name; do
        [ -n "$name" ] && echo "$IP $name"
    done < enum/dns/discovered-hostnames.txt > enum/dns/hosts-additions.txt
}

probe_discovered_hostnames() {
    local ports_to_probe name port scheme url code

    : > enum/web/discovered-host-web-probe.txt
    : > enum/web/discovered-host-web-urls.txt

    if [ ! -s enum/dns/discovered-hostnames.txt ]; then
        return 0
    fi

    ports_to_probe="$(ports_lines | grep -E '^(80|443|8000|8080|8443|3000|5000|9000|9090)$' | sort -nu | tr '\n' ' ')"
    [ -n "$ports_to_probe" ] || ports_to_probe="80 443"

    while read -r name; do
        [ -z "$name" ] && continue
        for port in $ports_to_probe; do
            for scheme in http https; do
                if [ "$scheme" = "http" ] && [ "$port" = "443" ]; then
                    continue
                fi
                if [ "$scheme" = "https" ] && [ "$port" = "80" ]; then
                    continue
                fi

                if [ "$port" = "80" ] || [ "$port" = "443" ]; then
                    url="$scheme://$name"
                else
                    url="$scheme://$name:$port"
                fi

                code="$(curl -k -s -o /dev/null -w "%{http_code}" --connect-timeout 2 --max-time 5 --resolve "$name:$port:$IP" "$url" || true)"
                echo "$url $code" | tee -a enum/web/discovered-host-web-probe.txt

                if [[ "$code" =~ ^(200|201|202|204|301|302|303|307|308|400|401|403|405|500|502|503)$ ]]; then
                    append_unique_line "$url" enum/web/discovered-host-web-urls.txt
                fi
            done
        done
    done < enum/dns/discovered-hostnames.txt
}

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

mkdir -p scans enum/{web,dns,smb,ftp,nfs,snmp,ldap,kerberos,rpc,winrm,ssh,other}
: > enum/dns/vhost-base-domains.txt
append_unique_line "$HOST" enum/dns/vhost-base-domains.txt

echo "[+] Starting recon for $BOX / $IP"
echo "[+] Hostname: $HOST"
echo "[+] Started at: $START_TIME"
echo "[+] Runtime knobs: RECON_DEEP=$RECON_DEEP WEB_ENUM=$WEB_ENUM FEROX_ENABLE=$FEROX_ENABLE FEROX_EXTENSIONS=$FEROX_EXTENSIONS FEROX_COLLECT=$FEROX_COLLECT FEROX_MAXTIME=$FEROX_MAXTIME FEROX_THREADS=$FEROX_THREADS FFUF_CONTENT=$FFUF_CONTENT FFUF_VHOST=$FFUF_VHOST FFUF_MAXTIME=$FFUF_MAXTIME FFUF_THREADS=$FFUF_THREADS FFUF_RATE=$FFUF_RATE MAX_WEB_URLS=$MAX_WEB_URLS MAX_WEB_WORDLISTS=$MAX_WEB_WORDLISTS MAX_FFUF_WORDLISTS=$MAX_FFUF_WORDLISTS"

echo
echo "=============================="
echo "[+] 0. Tool availability check"
echo "=============================="

for TOOL in nmap timeout whatweb feroxbuster ffuf nikto curl dig dnsrecon gobuster smbclient enum4linux-ng enum4linux smbmap showmount rpcinfo snmpwalk onesixtyone ldapsearch jq zip nc openssl ftp httpx nuclei netexec crackmapexec droopescan wpscan joomscan rg; do
    if have "$TOOL"; then
        echo "[+] $TOOL found"
    else
        echo "[-] $TOOL not found"
    fi
done | tee scans/tool-check.txt

if ! have nmap; then
    echo "[-] nmap is required."
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

nmap -p- --min-rate 5000 -Pn "$IP" -oN scans/tcp-full.txt

PORTS="$(grep -oP '^\d+/tcp\s+open' scans/tcp-full.txt | cut -d/ -f1 | paste -sd, - || true)"

if [ -z "$PORTS" ]; then
    echo "[-] No open TCP ports found."
    echo "[+] Continuing with UDP top ports scan only."

    nmap -sU -Pn --top-ports 100 "$IP" -oN scans/udp-top100.txt || true

    {
        echo "# Recon Summary - $BOX"
        echo
        echo "## Target"
        echo
        echo "- IP: $IP"
        echo "- Hostname: $HOST"
        echo
        echo "## Result"
        echo
        echo "No open TCP ports were discovered."
        echo
        echo "## Notes"
        echo
        echo "Verify HTB instance state, target IP, and VPN routing."
    } > summary.md

    if ! ./zip-recon.sh; then
        echo "[!] WARNING: Recon archive creation failed."
    fi

    exit 0
fi

echo "[+] Open TCP ports: $PORTS"
echo "$PORTS" > scans/open-tcp-ports.txt

echo
echo "======================================"
echo "[+] 2. TCP service/version enumeration"
echo "======================================"

nmap -sC -sV -Pn -p "$PORTS" "$IP" -oN scans/tcp-services.txt
nmap -A -Pn -p "$PORTS" "$IP" -oN scans/tcp-aggressive.txt || true
nmap --script default,safe -Pn -p "$PORTS" "$IP" -oN scans/tcp-default-safe-scripts.txt || true

echo
echo "=============================="
echo "[+] 3. UDP top ports scan"
echo "=============================="

nmap -sU -Pn --top-ports 100 "$IP" -oN scans/udp-top100.txt || true

echo
echo "=============================================="
echo "[+] 4. Web service discovery on all TCP ports"
echo "=============================================="

: > enum/web/web-candidates.txt
: > enum/web/live-web-urls.txt
: > enum/web/httpx-web-services.txt
: > enum/web/curl-web-probe.txt

for PORT in $(ports_lines); do
    case "$PORT" in
        21|22|25|53|88|110|111|135|139|143|389|445|464|593|636|993|995|1433|3268|3269|3389)
            continue
            ;;
    esac

    echo "http://$IP:$PORT" >> enum/web/web-candidates.txt
    echo "https://$IP:$PORT" >> enum/web/web-candidates.txt
done

USE_HTTPX=false

if have httpx; then
    if httpx -h 2>&1 | grep -q -- '-l'; then
        USE_HTTPX=true
    else
        echo "[!] httpx found, but it does not appear to be ProjectDiscovery httpx. Falling back to curl."
    fi
else
    echo "[-] httpx not found. Falling back to curl-based probing."
fi

if [ "$USE_HTTPX" = true ]; then
    echo "[+] ProjectDiscovery httpx found. Probing all open TCP ports for HTTP/HTTPS."

    httpx \
        -l enum/web/web-candidates.txt \
        -title \
        -tech-detect \
        -status-code \
        -follow-redirects \
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

        if [[ "$CODE" =~ ^(200|201|202|204|301|302|303|307|308|400|401|403|405|500|502|503)$ ]]; then
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

if [ -s enum/web/live-web-urls.txt ]; then
    WEB_URL_COUNT=0
    while read -r URL; do
        [ -z "$URL" ] && continue

        WEB_URL_COUNT=$((WEB_URL_COUNT + 1))
        if [ "$RECON_DEEP" != "1" ] && [ "$WEB_URL_COUNT" -gt "$MAX_WEB_URLS" ]; then
            echo "[!] Web URL budget reached at MAX_WEB_URLS=$MAX_WEB_URLS. Enable full coverage with RECON_DEEP=1."
            break
        fi

        SAFE_URL="$(safe_name "$URL")"
        PORT="$(url_port "$URL")"
        SCHEME="$(url_scheme "$URL")"

        if [ "$PORT" = "80" ] || [ "$PORT" = "443" ]; then
            HOST_URL="$SCHEME://$HOST"
        else
            HOST_URL="$SCHEME://$HOST:$PORT"
        fi

        echo
        echo "[+] Web target: $URL"
        echo "[+] Host URL candidate: $HOST_URL"

        if have whatweb; then
            whatweb "$URL" | tee "enum/web/whatweb-$SAFE_URL.txt" || true
            whatweb "$HOST_URL" | tee "enum/web/whatweb-host-$SAFE_URL.txt" || true
        fi

        if have curl; then
            curl -k -I "$URL" | tee "enum/web/headers-$SAFE_URL.txt" || true
            curl -k -I -H "Host: $HOST" "$URL" | tee "enum/web/headers-host-$SAFE_URL.txt" || true
            curl -k -s "$URL" -o "enum/web/index-$SAFE_URL.html" || true
            curl -k -s -H "Host: $HOST" "$URL" -o "enum/web/index-host-$SAFE_URL.html" || true

            for WEBPATH in robots.txt sitemap.xml security.txt .well-known/security.txt .well-known/jwks.json jwks.json openapi.json swagger.json api-docs; do
                SAFE_PATH="$(echo "$WEBPATH" | sed 's#[/]#_#g')"
                curl -k -s -i "$URL/$WEBPATH" -o "enum/web/${SAFE_PATH}-$SAFE_URL.txt" || true
                curl -k -s -i -H "Host: $HOST" "$URL/$WEBPATH" -o "enum/web/${SAFE_PATH}-host-$SAFE_URL.txt" || true
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

        while read -r JS; do
            [ -z "$JS" ] && continue

            if [[ "$JS" == http* ]]; then
                JS_URL="$JS"
            elif [[ "$JS" == /* ]]; then
                JS_URL="$SCHEME://$IP:$PORT$JS"
            else
                JS_URL="$URL/$JS"
            fi

            JS_SAFE_NAME="$(safe_name "$JS_URL")"

            if have curl; then
                curl -k -s "$JS_URL" -o "enum/web/js-$SAFE_URL-$JS_SAFE_NAME" || true
                curl -k -s -H "Host: $HOST" "$JS_URL" -o "enum/web/js-host-$SAFE_URL-$JS_SAFE_NAME" || true
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
        run_cms_specific_checks "$URL" "$SAFE_URL" "$TECH_PROFILE"

        if have nikto; then
            echo "[+] Running nikto"
            nikto -h "$URL" -output "enum/web/nikto-$SAFE_URL.txt" || true
        fi

        if [ "$SCHEME" = "https" ] && have openssl; then
            echo "[+] Running HTTPS/TLS checks"
            echo | openssl s_client -connect "$IP:$PORT" -servername "$HOST" 2>/dev/null \
                | openssl x509 -noout -text > "enum/web/cert-$SAFE_URL.txt" || true

            nmap --script ssl-cert,ssl-enum-ciphers -Pn -p "$PORT" "$IP" -oN "enum/web/nmap-ssl-$SAFE_URL.txt" || true
        fi

        if have nuclei; then
            echo "[+] Running nuclei"
            nuclei -u "$URL" -severity low,medium,high,critical -o "enum/web/nuclei-$SAFE_URL.txt" || true
        fi
    done < enum/web/live-web-urls.txt
else
    echo "[-] No web services detected."
fi

echo
echo "=============================="
echo "[+] 6. DNS enumeration"
echo "=============================="

if ports_lines | grep -q '^53$'; then
    if have dig; then
        dig @"$IP" "$HOST" A | tee enum/dns/dig-a.txt || true
        dig @"$IP" "$HOST" ANY | tee enum/dns/dig-any.txt || true
        dig @"$IP" "$HOST" NS | tee enum/dns/dig-ns.txt || true
        dig @"$IP" "$HOST" SOA | tee enum/dns/dig-soa.txt || true
        dig @"$IP" "$HOST" MX | tee enum/dns/dig-mx.txt || true
        dig @"$IP" "$HOST" TXT | tee enum/dns/dig-txt.txt || true
        dig axfr @"$IP" "$HOST" | tee enum/dns/axfr.txt || true
    fi

    if have dnsrecon; then
        dnsrecon -d "$HOST" -n "$IP" -a | tee enum/dns/dnsrecon.txt || true
    fi

    if have gobuster; then
        if [ -n "$DNS_WORDLIST" ]; then
            run_with_timeout 900 gobuster dns \
                -d "$HOST" \
                -r "$IP" \
                -w "$DNS_WORDLIST" \
                -o enum/dns/gobuster-dns.txt || true
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
    extract_dns_hostnames
    probe_discovered_hostnames
fi

echo
echo "=============================="
echo "[+] 7. SMB enumeration"
echo "=============================="

if ports_lines | grep -Eq '^(139|445)$'; then
    SMB_PORTS="$(ports_lines | grep -E '^(139|445)$' | paste -sd, -)"

    if have smbclient; then
        smbclient -L "\\\\$IP" -N | tee enum/smb/smbclient-null.txt || true
    fi

    if have enum4linux-ng; then
        timeout 180 enum4linux-ng "$IP" -oA enum/smb/enum4linux-ng || true
    elif have enum4linux; then
        timeout 180 enum4linux -a "$IP" | tee enum/smb/enum4linux.txt || true
    fi

    if have smbmap; then
        smbmap -H "$IP" | tee enum/smb/smbmap-null.txt || true
    fi

    nmap \
        --script smb-os-discovery,smb-enum-shares,smb-enum-users,smb-enum-groups,smb-enum-services,smb-enum-sessions,smb-security-mode,smb2-security-mode,smb2-time \
        -Pn \
        -p "$SMB_PORTS" "$IP" \
        -oN enum/smb/nmap-smb-enum.txt || true

    if have netexec; then
        netexec smb "$IP" | tee enum/smb/netexec-smb.txt || true
    fi

    if have crackmapexec; then
        crackmapexec smb "$IP" | tee enum/smb/cme-smb.txt || true
    fi
else
    echo "[-] SMB ports not detected."
fi

echo
echo "=============================="
echo "[+] 8. FTP enumeration"
echo "=============================="

if ports_lines | grep -q '^21$'; then
    nmap --script ftp-anon,ftp-syst,ftp-bounce -Pn -p21 "$IP" -oN enum/ftp/nmap-ftp.txt || true

    if have ftp; then
        printf "anonymous\nanonymous@\nbye\n" | ftp -inv "$IP" 2>&1 | tee enum/ftp/ftp-anonymous-check.txt || true
    fi
else
    echo "[-] FTP port not detected."
fi

echo
echo "=============================="
echo "[+] 9. SSH enumeration"
echo "=============================="

if ports_lines | grep -q '^22$'; then
    nmap --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -Pn -p22 "$IP" -oN enum/ssh/nmap-ssh.txt || true

    if have nc; then
        nc -nv "$IP" 22 2>&1 | tee enum/ssh/ssh-banner.txt || true
    fi
else
    echo "[-] SSH port not detected."
fi

echo
echo "=============================="
echo "[+] 10. NFS enumeration"
echo "=============================="

if ports_lines | grep -Eq '^(111|2049)$'; then
    NFS_PORTS="$(ports_lines | grep -E '^(111|2049)$' | paste -sd, -)"

    if have showmount; then
        showmount -e "$IP" | tee enum/nfs/showmount.txt || true
    fi

    nmap --script nfs-ls,nfs-showmount,nfs-statfs -Pn -p "$NFS_PORTS" "$IP" -oN enum/nfs/nmap-nfs.txt || true
else
    echo "[-] NFS/RPCBind ports not detected."
fi

echo
echo "=============================="
echo "[+] 11. RPC enumeration"
echo "=============================="

if ports_lines | grep -q '^111$'; then
    if have rpcinfo; then
        rpcinfo -p "$IP" | tee enum/rpc/rpcinfo.txt || true
    fi

    nmap --script rpc-grind,rpcinfo -Pn -p111 "$IP" -oN enum/rpc/nmap-rpc.txt || true
else
    echo "[-] RPCBind port not detected."
fi

echo
echo "=============================="
echo "[+] 12. SNMP enumeration"
echo "=============================="

if grep -q '161/udp.*open' scans/udp-top100.txt 2>/dev/null; then
    if have onesixtyone; then
        if [ -n "$SNMP_WORDLIST" ]; then
            onesixtyone -c "$SNMP_WORDLIST" "$IP" | tee enum/snmp/onesixtyone.txt || true
        else
            echo "[!] Skipping onesixtyone: no SNMP community wordlist found."
        fi
    fi

    if have snmpwalk; then
        snmpwalk -v2c -c public "$IP" | tee enum/snmp/snmpwalk-public.txt || true
    fi

    nmap -sU --script snmp-info,snmp-interfaces,snmp-processes,snmp-sysdescr -Pn -p161 "$IP" -oN enum/snmp/nmap-snmp.txt || true
else
    echo "[-] SNMP UDP/161 not detected in top UDP scan."
fi

echo
echo "=============================="
echo "[+] 13. LDAP enumeration"
echo "=============================="

if ports_lines | grep -Eq '^(389|636|3268|3269)$'; then
    LDAP_PORTS="$(ports_lines | grep -E '^(389|636|3268|3269)$' | paste -sd, -)"

    nmap --script ldap-rootdse,ldap-search -Pn -p "$LDAP_PORTS" "$IP" -oN enum/ldap/nmap-ldap.txt || true

    if have ldapsearch; then
        ldapsearch -x -H "ldap://$IP" -s base namingcontexts | tee enum/ldap/namingcontexts.txt || true
    fi
else
    echo "[-] LDAP ports not detected."
fi

echo
echo "=============================="
echo "[+] 14. Kerberos enumeration"
echo "=============================="

if ports_lines | grep -q '^88$'; then
    nmap --script krb5-enum-users -Pn -p88 "$IP" -oN enum/kerberos/nmap-kerberos.txt || true
else
    echo "[-] Kerberos port not detected."
fi

echo
echo "=============================="
echo "[+] 15. WinRM enumeration"
echo "=============================="

if ports_lines | grep -Eq '^(5985|5986)$'; then
    WINRM_PORTS="$(ports_lines | grep -E '^(5985|5986)$' | paste -sd, -)"

    nmap -sV -Pn -p "$WINRM_PORTS" "$IP" -oN enum/winrm/nmap-winrm.txt || true

    if have netexec; then
        netexec winrm "$IP" | tee enum/winrm/netexec-winrm.txt || true
    fi

    if have crackmapexec; then
        crackmapexec winrm "$IP" | tee enum/winrm/cme-winrm.txt || true
    fi
else
    echo "[-] WinRM ports not detected."
fi

echo
echo "=============================="
echo "[+] 16. Generate port summary"
echo "=============================="

{
    echo "# Port Summary"
    echo
    echo "| Port | Service | Version | Notes |"
    echo "|---:|---|---|---|"
    awk '/^[0-9]+\/tcp[[:space:]]+open/ {
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
echo "[+] 17. Optional vulnerability Nmap scan"
echo "========================================="

echo "[+] This scan can be slow/noisy. Treat results as hints."
nmap --script vuln -Pn -p "$PORTS" "$IP" -oN scans/tcp-vuln.txt || true

echo
echo "=============================="
echo "[+] 18. Interesting grep"
echo "=============================="

grep -RniI \
    --exclude="interesting-grep.txt" \
    --exclude="summary.md" \
    --exclude="recon-console.log" \
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
echo "[+] 19. Generate recon summary"
echo "=============================="

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
    echo "## Open TCP Ports"
    echo
    cat scans/port-summary.md 2>/dev/null || true
    echo
    echo "## Service Scan"
    echo
    grep -E '^[0-9]+/tcp\s+open' scans/tcp-services.txt 2>/dev/null || true
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
    grep -RniI \
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
echo "[+] Recon complete."
echo "[+] Main files to review:"
echo "    summary.md"
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
echo "[+] 20. Creating recon archive"
echo "=============================="

if ! ./zip-recon.sh; then
    echo "[!] WARNING: Recon archive creation failed."
fi

END_TIME="$(date)"
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

## Recommended Launch Flow

\`\`\`bash
cd $BASE_DIR
./update-hosts.sh
./recon.sh
less summary.md
\`\`\`

## Main Files

* .target.env - machine-local config
* summary.md - generated recon summary
* notes.md - working notes
* writeup.md - final report/writeup
* recon.sh - automated first-stage recon
* search-recon.sh - search collected recon and optionally copy matched files
* file-hunt.sh - find readable files by name pattern and copy matches to loot
* update-hosts.sh - update /etc/hosts for this box
* zip-recon.sh - archive recon results
* privesc-linux.md - local Linux privilege escalation checklist
* recon-console.log - full terminal output from recon
* scans/ - Nmap outputs
* enum/ - service-specific enumeration outputs

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

Default recon is conservative to avoid ffuf/ferox loops on dynamic targets.

\`\`\`bash
./recon.sh
# Fast default recon
./recon.sh

# Disable all heavy web fuzzing
WEB_ENUM=0 ./recon.sh

# Run ferox but without extension multiplication or collect-backups
FEROX_EXTENSIONS=0 FEROX_COLLECT=0 ./recon.sh

# Deep mode when the quick pass is finished
RECON_DEEP=1 FEROX_EXTENSIONS=1 FEROX_COLLECT=1 FFUF_CONTENT=1 ./recon.sh
FFUF_RATE=40 FFUF_THREADS=10 FFUF_MAXTIME=180 ./recon.sh
FFUF_VHOST=0 ./recon.sh
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
