# htb-init

`htb-init` is a Bash-based Hack The Box workspace initializer and first-stage recon automation helper.

It creates a clean workspace for a new HTB machine, generates target configuration, helper scripts, starter notes, a writeup template, a Linux privilege escalation checklist, automated recon tooling, and a ZIP archive helper.

The repository also includes `analyze-recon.py`, a standalone offline analysis helper that reviews collected recon output and generates prioritized next-step suggestions.

The workflow is intended for  Hack The Box labs.

---

## Features

- Creates a structured workspace under `/home/zendeni/htb_labs/<box>/`
- Generates a machine-local `.target.env`
- Generates an `/etc/hosts` update helper
- Generates an automated `recon.sh` script
- Generates a recon ZIP archive helper
- Generates starter `notes.md` and `writeup.md`
- Generates a Linux privilege escalation checklist
- Runs service-aware enumeration based on discovered ports
- Performs TCP and UDP discovery
- Performs web discovery with `httpx` when ProjectDiscovery `httpx` is available
- Falls back to curl-based HTTP/HTTPS probing when ProjectDiscovery `httpx` is not available
- Uses faster timeout-safe curl probing for Windows/AD-style targets
- Avoids wasting time on obvious non-web AD ports during web probing
- Runs service-specific enumeration for DNS, SMB, FTP, SSH, NFS/RPC, SNMP, LDAP, Kerberos, and WinRM
- Wraps noisy/hanging SMB tools such as `enum4linux` with a timeout
- Saves console output and recon summaries
- Automatically creates a ZIP archive after recon
- Avoids overwriting existing `notes.md` and `writeup.md`
- Provides optional offline recon interpretation through `analyze-recon.py`

---

## Repository Structure

```text
htb-init/
├── README.md
├── htb-init.sh
└── analyze-recon.py
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Zendeni/htb-init.git
cd htb-init
```

Make the scripts executable:

```bash
chmod +x htb-init.sh
chmod +x analyze-recon.py
```

Install `htb-init` as a system command:

```bash
sudo cp htb-init.sh /usr/local/bin/htb-init
sudo chmod +x /usr/local/bin/htb-init
```

Optional: install `analyze-recon.py` into your HTB tools folder:

```bash
mkdir -p /home/zendeni/tools/htb
cp analyze-recon.py /home/zendeni/tools/htb/analyze-recon.py
chmod +x /home/zendeni/tools/htb/analyze-recon.py
```

Confirm installation:

```bash
which htb-init
head -n 1 "$(which htb-init)"
bash -n "$(which htb-init)" && echo "syntax OK"
```

Expected:

```text
/usr/local/bin/htb-init
#!/usr/bin/env bash
syntax OK
```

---

## Usage

```bash
htb-init <box-name> <target-ip>
```

Example:

```bash
htb-init principal 10.129.244.220
```

Use the short box name only. Do **not** include `.htb`.

Correct:

```bash
htb-init principal 10.129.244.220
```

Wrong:

```bash
htb-init principal.htb 10.129.244.220
```

This creates:

```text
/home/zendeni/htb_labs/principal
```

and configures:

```text
BOX="principal"
IP="10.129.244.220"
HOST="principal.htb"
BASE_DIR="/home/zendeni/htb_labs/principal"
```

---

## Requirements

The script expects a Linux/Kali-style environment.

Required:

```bash
bash
sudo
awk
getent
nmap
timeout
zip
```

Strongly recommended:

```bash
curl
whatweb
feroxbuster
ffuf
nikto
dig
dnsrecon
gobuster
smbclient
enum4linux-ng
enum4linux
smbmap
showmount
rpcinfo
snmpwalk
onesixtyone
ldapsearch
jq
nc
openssl
ftp
```

Optional but useful:

```bash
httpx
nuclei
netexec
crackmapexec
```

Notes:

- If ProjectDiscovery `httpx` is available, `recon.sh` uses it for HTTP/HTTPS probing.
- If another tool named `httpx` is installed, `recon.sh` detects this and falls back to curl.
- If `httpx` is missing entirely, `recon.sh` also falls back to curl.
- `enum4linux` and `enum4linux-ng` are useful but can be noisy or slow on Windows/AD targets, so they are timeout-wrapped.

---

## What It Creates

```text
/home/zendeni/htb_labs/<box>/
├── .target.env
├── update-hosts.sh
├── recon.sh
├── zip-recon.sh
├── privesc-linux.md
├── notes.md
├── writeup.md
├── README.md
├── scans/
├── enum/
│   ├── web/
│   ├── dns/
│   ├── smb/
│   ├── ftp/
│   ├── nfs/
│   ├── snmp/
│   ├── ldap/
│   ├── kerberos/
│   ├── rpc/
│   ├── winrm/
│   ├── ssh/
│   └── other/
├── loot/
├── exploits/
├── shells/
├── screenshots/
└── tools/
```

After `recon.sh` runs, it also creates:

```text
summary.md
recon-console.log
<box>-recon-<timestamp>.zip
```

If `analyze-recon.py` is run against the workspace, it creates:

```text
recon-analysis.md
```

---

## Main Generated Files

### `.target.env`

Stores machine-specific variables used by the helper scripts:

```bash
BOX="principal"
IP="10.129.244.220"
HOST="principal.htb"
BASE_DIR="/home/zendeni/htb_labs/principal"
```

The generated helper scripts source this file, which makes them location-aware and reusable.

---

### `update-hosts.sh`

Safely updates `/etc/hosts` for the current target.

Run it from inside the box folder:

```bash
./update-hosts.sh
```

It removes old entries for the same hostname and adds the current one:

```text
10.129.244.220 principal.htb
```

The script avoids unsafe regex-based deletion and updates only entries where the hostname matches as a field.

---

### `recon.sh`

Runs automated first-stage recon against the target.

Run:

```bash
./recon.sh
```

It performs:

```text
- Tool availability check
- Full TCP port scan
- TCP service/version enumeration
- TCP aggressive scan
- TCP default/safe Nmap scripts
- UDP top ports scan
- HTTP/HTTPS discovery
- Web enumeration with whatweb, curl, feroxbuster, ffuf, nikto
- Host-header web checks
- JavaScript extraction and keyword grep
- DNS enumeration if port 53 is open
- SMB enumeration if ports 139/445 are open
- FTP enumeration if port 21 is open
- SSH enumeration if port 22 is open
- NFS/RPC enumeration if relevant ports are open
- SNMP enumeration if UDP/161 is found
- LDAP enumeration if LDAP ports are open
- Kerberos enumeration if port 88 is open
- WinRM enumeration if ports 5985/5986 are open
- Optional Nmap vulnerability script scan
- Interesting keyword grep
- Recon summary generation
- Automatic ZIP archive generation
```

Important generated outputs:

```text
summary.md
recon-console.log
scans/tcp-full.txt
scans/tcp-services.txt
scans/tcp-aggressive.txt
scans/tcp-default-safe-scripts.txt
scans/tcp-vuln.txt
scans/udp-top100.txt
scans/port-summary.md
enum/web/live-web-urls.txt
enum/web/curl-web-probe.txt
enum/interesting-grep.txt
```

---

### `zip-recon.sh`

Creates a ZIP archive of recon material.

Run manually with:

```bash
./zip-recon.sh
```

`recon.sh` also runs it automatically at the end.

The archive includes:

```text
.target.env
scans/
enum/
notes.md
writeup.md
README.md
recon.sh
update-hosts.sh
zip-recon.sh
privesc-linux.md
summary.md
recon-console.log
```

It excludes bulky or sensitive folders/files:

```text
loot/
exploits/
shells/
screenshots/
*.pcap
*.cap
*.zip
```

---

### `notes.md`

Working notes for:

```text
- Target info
- Open ports
- Credentials
- Interesting findings
- Attack ideas
- Foothold
- Privilege escalation
- Loot
- Proofs
```

If `notes.md` already exists, `htb-init` leaves it unchanged.

---

### `writeup.md`

Starter writeup template with sections for:

```text
- Enumeration
- Initial access
- Local enumeration
- Privilege escalation
- Attack chain summary
- MITRE ATT&CK mapping
- Remediation summary
```

If `writeup.md` already exists, `htb-init` leaves it unchanged.

---

### `privesc-linux.md`

Linux privilege escalation checklist covering:

```text
- Current user/context
- sudo permissions
- Users and groups
- SUID/SGID binaries
- Capabilities
- Writable paths
- Processes/services
- Cron jobs
- Interesting files
- Shell stabilization
```

---

## Optional: `analyze-recon.py`

`analyze-recon.py` is a standalone offline recon analysis helper.

It does **not** run exploitation. It does **not** modify the target. It reads collected recon output and generates a prioritized analysis report.

It supports:

```text
- Extracted HTB workspace folders
- ZIP archives generated by zip-recon.sh
```

Example against a workspace folder:

```bash
python3 analyze-recon.py /home/zendeni/htb_labs/principal
```

Example against a recon ZIP:

```bash
python3 analyze-recon.py /home/zendeni/htb_labs/principal/principal-recon-20260524-135821.zip
```

It generates:

```text
recon-analysis.md
```

Depending on the available data, it attempts to extract and summarize:

```text
- Target metadata
- Open ports
- Detected services
- Detected technologies
- Likely machine profile
- Web URLs
- Web headers
- Forms and input fields
- JavaScript references
- API endpoints
- Authentication-related clues
- SMB shares
- LDAP naming contexts
- AD/DC indicators
- MSSQL indicators
- WinRM indicators
- High-value next steps
- CVE/research search suggestions
- Interesting grep highlights
```

Example output sections:

```text
Detected Profile
Open Ports
Detected Technologies
Web Intelligence
AD / SMB / LDAP Intelligence
Prioritized Findings and Next Steps
CVE / Research Search Suggestions
Interesting Grep Highlights
Files Parsed
```

Treat all suggestions from `analyze-recon.py` as hypotheses requiring manual validation.

---

## Recommended Workflow

### 1. Initialize the box

```bash
htb-init principal 10.129.244.220
```

### 2. Enter the workspace

```bash
cd /home/zendeni/htb_labs/principal
```

### 3. Update `/etc/hosts`

```bash
./update-hosts.sh
```

### 4. Run recon

```bash
./recon.sh
```

### 5. Review the raw recon summary

```bash
less summary.md
```

### 6. Optionally run recon analysis

From the repository folder:

```bash
python3 /home/zendeni/tools/htb/analyze-recon.py /home/zendeni/htb_labs/principal
```

Or, if `analyze-recon.py` is in the current repository folder:

```bash
python3 analyze-recon.py /home/zendeni/htb_labs/principal
```

Then review:

```bash
less /home/zendeni/htb_labs/principal/recon-analysis.md
```

---

## Useful Review Commands

```bash
cat scans/open-tcp-ports.txt
cat scans/port-summary.md
cat enum/web/live-web-urls.txt
cat enum/web/curl-web-probe.txt
cat enum/interesting-grep.txt
less summary.md
```

For Windows/AD-style boxes:

```bash
cat enum/smb/smbclient-null.txt 2>/dev/null
cat enum/smb/netexec-smb.txt 2>/dev/null
cat enum/ldap/namingcontexts.txt 2>/dev/null
cat enum/winrm/netexec-winrm.txt 2>/dev/null
cat scans/port-summary.md
```

For web-heavy boxes:

```bash
cat enum/web/live-web-urls.txt
grep -RniE "fetch|axios|/api/|token|auth|login|admin|dashboard|password|secret" enum/web/
find enum/web -type f -size +0c | sort
```

---

## Safety and Validation

`htb-init` validates:

```text
- Box name format
- Short box name only, not box.htb
- IPv4 address format
- IPv4 octets between 0 and 255
```

It does **not** overwrite existing:

```text
notes.md
writeup.md
```

This prevents accidental loss of manual notes or report work when rerunning `htb-init`.

The recon workflow is intended for authorized lab targets only.

---

## Example

```bash
htb-init bounty 10.129.37.20
cd /home/zendeni/htb_labs/bounty
./update-hosts.sh
./recon.sh
less summary.md
```

Result:

```text
/home/zendeni/htb_labs/bounty/
```

with:

```text
bounty.htb
10.129.37.20
```

and a generated archive like:

```text
bounty-recon-20260524-153000.zip
```

Optional analysis:

```bash
python3 /home/zendeni/tools/htb/analyze-recon.py /home/zendeni/htb_labs/bounty
less /home/zendeni/htb_labs/bounty/recon-analysis.md
```

---

## Notes

This tool is designed for personal HTB methodology, repeatability, and clean writeup preparation.

It does not perform exploitation. It creates a workspace, runs first-stage enumeration, packages recon data, and optionally analyzes collected recon artifacts for likely next steps.

Keep `htb-init.sh` stable. Develop and improve `analyze-recon.py` separately so recon collection remains reliable.
