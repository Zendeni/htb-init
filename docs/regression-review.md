# Collector and analyzer regression review

The tests in this change use synthetic evidence, mocked collection tools and
temporary localhost HTTP servers. They do not scan a lab or external application.

## Confirmed bugs fixed

| Problem | Effect | Regression coverage |
| --- | --- | --- |
| Separate vulnerability/default-safe NSE calls omitted `-sV` | The earlier service scan's version/CPE data was unavailable to scripts in these calls | Inspect executed Nmap arguments, verify XML and text artifacts |
| Open-port extraction also accepted `open\|filtered` | Unconfirmed ports entered downstream enumeration | Mixed-state mocked Nmap output |
| Web discovery rejected HTTP 404 and other valid responses | Existing web servers could be omitted | Mocked 404 discovery |
| No common web port caused a failing pipeline under `pipefail` | SSH-only recon stopped before completion | Full SSH-only collector run |
| Vhost probes only used a fixed port list | HTTP services on other ports were missed | HTTP on port 12345 |
| Persistent ffuf completion markers survived failed/previous runs | Later enumeration was skipped | Stale-marker and repeated-run scenarios |
| Priority vhost list required an unrelated installed DNS list | Built-in list was never used without SecLists | Run with only generated priority list |
| Empty wordlist counting returned a failed grep status | Empty inputs could abort recon | Mocked generated collector workflow |
| Alternation patterns used basic grep syntax | Useful headers/secrets were absent from summaries | Known fixture markers in final evidence/summary |
| Empty-port runs retained old target manifests | Later work could act on stale targets | Prepopulate manifests then simulate no open ports |
| Heavy CMS/Nikto work ignored `WEB_ENUM=0` | Disabling web enumeration did not stop those scanners | CMS-rich fixture with scanners disabled |
| Analyzer keyed services only by port number | TCP and UDP entries collided, and UDP rows could create phantom TCP services | Mixed 53/tcp + 53/udp and protocol-specific findings |
| Nmap parser rejected CRLF lines | Windows-style evidence silently lost services | CRLF fixture |
| npm constraints were stripped into fake exact versions | OSV queried versions not established by evidence | Exact, caret, tilde and range manifests |
| Valid non-object package JSON was not type-checked | One malformed artifact aborted the report | Lists/scalars in package/lock files |
| Nested npm installation paths were treated as registry names | OSV queried incorrect package names | Nested, scoped and workspace lock entries |
| Generic banner products were sent to OSV | Unsupported ecosystems contaminated package lookups | Mixed/generic-only batches with mocked API |

## New web assessment verification

The web helper tests cover scope inclusion/exclusion, malformed URLs, credentials,
controls, invalid ports, CIDRs, metadata not being sourced, independent report
directories, missing tools/templates, identical inventory and execution filters,
DAST/OAST flags, failed and timed-out scanners, invalid JSONL, and findings exit
codes. Local HTTP tests cover redirects, forms, page/endpoint/body-size limits,
and slow headers/bodies. Fetches use subprocess deadlines because socket
inactivity timeouts alone do not bound a slow server's total response time.

Generated-workspace tests verify helper copying, external-current-directory use,
interpreter selection, one automatic invocation after discovery, status handling,
and disabling the assessor.

A separate real-engine smoke test used Nuclei 3.11.1 and unmodified signed
`nginx-version` and `reflected-xss` templates against an ephemeral localhost
fixture. Both stages completed, both expected findings were produced, and the
helper returned exit code 1. This verifies the command interface and representative
HTTP/DAST behavior; it does not validate every community template.

## Remaining review work

- Reconcile any unpublished Kali VM changes with this branch before merging.
- Exercise the intended Kali/Nmap/tool versions on an authorized lab after the
  offline suite passes. Third-party scanner versions, templates and networking
  can affect behavior beyond the mocked collector tests.
- Use the generated OWASP checklist for authenticated flows, XML/JSON/POST bodies,
  authorization and business logic. Automated completion is not complete coverage.
- Legacy analyzer vulnerability cache entries currently have no TTL; refresh or
  remove a stale cache before relying on an online enrichment review.
- Legacy report wording can group local CVE hints under an online-intelligence
  heading; inspect each finding's source. ScopeLens has its own separate reporting
  implementation.
- The older collector has its own redirect, vhost and JavaScript fetching behavior.
  The new assessor's explicit target filtering does not retrofit that entire
  collector into a network sandbox.

Run the suite from the checkout with the pinned ScopeLens dependency installed:

```bash
bash -n htb-init.sh
python -m unittest discover -s tests -v
```
