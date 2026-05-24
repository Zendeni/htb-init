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

mkdir -p "$BASE_DIR"/{scans,enum/{web,dns,smb,ftp,nfs,snmp,ldap,kerberos,rpc,winrm,ssh,other},loot,exploits,shells,screenshots,tools}
cd "$BASE_DIR"

cat > .target.env <<EOF
BOX="$BOX"
IP="$IP"
HOST="$HOST"
BASE_DIR="$BASE_DIR"
EOF

cat > update-hosts.sh <<'EOF'
#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source ./.target.env

tmpfile="$(mktemp)"
trap 'rm -f "$tmpfile"' EXIT

echo "[+] Updating /etc/hosts for $HOST"

awk -v host="$HOST" '
{
    keep = 1
    for (i = 2; i <= NF; i++) {
        if ($i == host) keep = 0
    }
    if (keep) print
}
' /etc/hosts > "$tmpfile"

echo "$IP $HOST" >> "$tmpfile"
sudo cp "$tmpfile" /etc/hosts

echo "[+] Current hosts entry:"
getent hosts "$HOST" || true
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

The target machine \`$BOX\` was assessed as part of an authorized Hack The Box lab.

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
feroxbuster -u <url> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt,html,js,bak,old,zip,tar,gz,conf,config,json,yml,xml,log -k
ffuf -ac -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u <url>/ -H "Host: FUZZ.$HOST"
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

cat > recon.sh <<'EOF'
#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source ./.target.env

exec > >(tee -a recon-console.log) 2>&1

START_TIME="$(date)"

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

safe_name() {
    echo "$1" | sed 's#[/:?&=.]#_#g'
}

mkdir -p scans enum/{web,dns,smb,ftp,nfs,snmp,ldap,kerberos,rpc,winrm,ssh,other}

echo "[+] Starting recon for $BOX / $IP"
echo "[+] Hostname: $HOST"
echo "[+] Started at: $START_TIME"

echo
echo "=============================="
echo "[+] 0. Tool availability check"
echo "=============================="

for TOOL in nmap whatweb feroxbuster ffuf nikto curl dig dnsrecon gobuster smbclient enum4linux-ng enum4linux smbmap showmount rpcinfo snmpwalk onesixtyone ldapsearch jq zip nc openssl ftp httpx nuclei netexec crackmapexec; do
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
    echo "http://$IP:$PORT" >> enum/web/web-candidates.txt
    echo "https://$IP:$PORT" >> enum/web/web-candidates.txt
done

if have httpx; then
    echo "[+] httpx found. Probing all open TCP ports for HTTP/HTTPS."

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
else
    echo "[-] httpx not found. Falling back to curl-based probing."

    while read -r URL; do
        [ -z "$URL" ] && continue

        CODE="$(curl -k -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$URL" || true)"
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
    while read -r URL; do
        [ -z "$URL" ] && continue

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

        grep -RiE "api|admin|login|token|jwt|auth|secret|\bkey\b|debug|dashboard|credentials?|password|jwks|jwe|jws|pac4j" \
            enum/web/js-* 2>/dev/null | tee "enum/web/js-interesting-$SAFE_URL.txt" || true

        if have feroxbuster; then
            echo "[+] Running feroxbuster"
            feroxbuster \
                -u "$URL" \
                -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
                -x php,txt,html,js,bak,old,zip,tar,gz,conf,config,json,yml,xml,log \
                -k \
                --auto-tune \
                --collect-words \
                --collect-backups \
                -o "enum/web/ferox-$SAFE_URL.txt" || true
        fi

        if have ffuf; then
            echo "[+] Running ffuf vhost discovery"
            ffuf \
                -ac \
                -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
                -u "$URL/" \
                -H "Host: FUZZ.$HOST" \
                -o "enum/web/ffuf-vhosts-$SAFE_URL.json" || true
        fi

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
        gobuster dns \
            -d "$HOST" \
            -r "$IP" \
            -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
            -o enum/dns/gobuster-dns.txt || true
    fi
else
    echo "[-] DNS port not detected."
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
        enum4linux-ng "$IP" -oA enum/smb/enum4linux-ng || true
    elif have enum4linux; then
        enum4linux -a "$IP" | tee enum/smb/enum4linux.txt || true
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
        onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt "$IP" | tee enum/snmp/onesixtyone.txt || true
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

grep -RiE "admin|login|dashboard|api|jwt|token|auth|credentials?|password|passwd|ssh|private key|id_rsa|backup|bak|old|debug|dev|test|staging|pac4j|jwe|jws|jwks|principal|root|secret|\bkey\b" \
    scans enum 2>/dev/null | tee enum/interesting-grep.txt || true

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
    echo "## HTTPX Web Services"
    echo
    cat enum/web/httpx-web-services.txt 2>/dev/null || true
    echo
    echo "## Web Fingerprinting"
    echo
    cat enum/web/whatweb-*.txt 2>/dev/null || true
    echo
    echo "## Interesting Web Headers"
    echo
    grep -RiE "server:|x-powered-by:|set-cookie:|location:|authorization|jwt|token|pac4j|spring|jetty|tomcat|nginx|apache" enum/web/ 2>/dev/null || true
    echo
    echo "## Ferox Results"
    echo
    grep -hE "^[0-9]{3}" enum/web/ferox-*.txt 2>/dev/null || true
    echo
    echo "## FFUF Vhost Results"
    echo
    if have jq; then
        for f in enum/web/ffuf-vhosts-*.json; do
            [ -f "$f" ] && jq -r '.results[]? | "\(.status) \(.length) \(.words) \(.host) \(.url)"' "$f" 2>/dev/null || true
        done
    else
        cat enum/web/ffuf-vhosts-*.json 2>/dev/null || true
    fi
    echo
    echo "## Interesting Grep Results"
    echo
    cat enum/interesting-grep.txt 2>/dev/null || true
    echo
    echo "## Files To Review"
    echo
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

- Box: \`$BOX\`
- IP: \`$IP\`
- Hostname: \`$HOST\`

## Recommended Launch Flow

\`\`\`bash
cd $BASE_DIR
./update-hosts.sh
./recon.sh
less summary.md
\`\`\`

## Main Files

- \`.target.env\` - machine-local config
- \`summary.md\` - generated recon summary
- \`notes.md\` - working notes
- \`writeup.md\` - final report/writeup
- \`recon.sh\` - automated first-stage recon
- \`update-hosts.sh\` - update /etc/hosts for this box
- \`zip-recon.sh\` - archive recon results
- \`privesc-linux.md\` - local Linux privilege escalation checklist
- \`recon-console.log\` - full terminal output from recon
- \`scans/\` - Nmap outputs
- \`enum/\` - service-specific enumeration outputs

## Useful Review Commands

\`\`\`bash
cat scans/open-tcp-ports.txt
cat scans/port-summary.md
cat enum/web/live-web-urls.txt
cat enum/interesting-grep.txt
less summary.md
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
