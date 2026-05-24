# htb-init

`htb-init` is a small Bash helper script for creating a clean Hack The Box workspace for a new machine.

It creates the folder structure, target configuration, helper scripts, starter notes, a writeup template, and a recon archive helper.

## Usage

```bash
htb-init <box-name> <target-ip>
```

Example:

```bash
htb-init principal 10.129.244.220
```

This creates:

```bash
/home/zendeni/htb_labs/principal
```

and configures:

```bash
principal.htb
10.129.244.220
```

## Requirements

The script expects a Linux/Kali-style environment with common tools installed.

Required:

```bash
bash
sudo
awk
getent
zip
```

Recommended for the generated workflow:

```bash
nmap
whatweb
feroxbuster
ffuf
curl
```

## What It Creates

```text
/home/zendeni/htb_labs/<box>/
├── .target.env
├── update-hosts.sh
├── zip-recon.sh
├── notes.md
├── writeup.md
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

## Main Files

### `.target.env`

Stores machine-specific variables:

```bash
BOX="principal"
IP="10.129.244.220"
HOST="principal.htb"
BASE_DIR="/home/zendeni/htb_labs/principal"
```

This lets helper scripts stay location-aware.

### `update-hosts.sh`

Updates `/etc/hosts` for the current target.

Run it from inside the box folder:

```bash
./update-hosts.sh
```

It safely removes old entries for the same hostname and adds the current one:

```text
10.129.244.220 principal.htb
```

### `notes.md`

A working notes file for enumeration, credentials, findings, attack ideas, foothold, privilege escalation, and proofs.

### `writeup.md`

A starter writeup template with sections for:

* Enumeration
* Initial access
* Local enumeration
* Privilege escalation
* Attack chain summary
* MITRE ATT&CK mapping
* Remediation summary

### `zip-recon.sh`

Creates a ZIP archive of the recon material while excluding sensitive or bulky folders such as:

```text
loot/
exploits/
shells/
screenshots/
*.pcap
*.cap
*.zip
```

Run it with:

```bash
./zip-recon.sh
```

## Recommended Workflow

```bash
htb-init principal 10.129.244.220
cd /home/zendeni/htb_labs/principal
./update-hosts.sh
```

Then begin enumeration manually or with your own recon script:

```bash
nmap -p- --min-rate 5000 -Pn 10.129.244.220 -oN scans/tcp-full.txt
```

After recon, archive the clean results:

```bash
./zip-recon.sh
```

## Safety Notes

The script validates:

* Box name format
* Short box name only, not `box.htb`
* IPv4 format
* IPv4 octets must be between `0` and `255`

It does not overwrite existing `notes.md` or `writeup.md`.

## Example

```bash
htb-init bounty 10.129.37.20
cd /home/zendeni/htb_labs/bounty
./update-hosts.sh
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
