# htb-init

`htb-init` is a Bash-based Hack The Box workspace initializer and first-stage recon automation helper.

It creates a clean workspace for a new HTB machine, generates target configuration, helper scripts, starter notes, a writeup template, a Linux privilege escalation checklist, automated recon tooling, and a ZIP archive helper.

The generated workflow is intended for authorized HTB labs only.

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

## Installation

Place `htb-init` somewhere in your PATH.

Example:

```bash
chmod +x htb-init
sudo mv htb-init /usr/local/bin/htb-init
```

Confirm:

```bash
which htb-init
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

If `httpx` is missing, the generated `recon.sh` falls back to curl-based HTTP/HTTPS probing.

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

After `recon.sh` runs, it also creates files such as:

```text
summary.md
recon-console.log
<box>-recon-<timestamp>.zip
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

Run:

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
- TCP default/safe Nmap scripts
- UDP top ports scan
- HTTP/HTTPS discovery across all open TCP ports
- Web enumeration with whatweb, curl, feroxbuster, ffuf, nikto
- Host-header web checks
- JavaScript extraction and keyword grep
- DNS enumeration if port 53 is open
- SMB enumeration if ports 139/445 are open
- FTP enumeration if port 21 is open
- SSH enumeration if port 22 is open
- NFS/RPC enumeration if relevant ports are open
- SNMP enumeration if UDP/161 is found
- LDAP/Kerberos/WinRM enumeration if relevant ports are open
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
scans/tcp-vuln.txt
scans/udp-top100.txt
scans/port-summary.md
enum/web/live-web-urls.txt
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
- users/groups
- SUID/SGID binaries
- capabilities
- writable paths
- processes/services
- cron jobs
- interesting files
- shell stabilization
```

---

## Recommended Workflow

```bash
htb-init principal 10.129.244.220
cd /home/zendeni/htb_labs/principal
./update-hosts.sh
./recon.sh
less summary.md
```

Useful review commands:

```bash
cat scans/open-tcp-ports.txt
cat scans/port-summary.md
cat enum/web/live-web-urls.txt
cat enum/interesting-grep.txt
less summary.md
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
