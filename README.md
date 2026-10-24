# htb-init + ScopeLens

**Prepare a workspace, inspect the evidence, and open a readable report.**

[htb-init](https://github.com/Zendeni/htb-init) creates HTB workspaces. [ScopeLens](https://github.com/Zendeni/scopelens) provides their shared offline analysis workflow: artifact coverage, evidence-backed findings, searchable HTML, JSON, Markdown, and comparisons between reviews.

The integration uses ScopeLens **0.2.0 or newer** and Python **3.10 or newer**. The initializer and generated shell helpers require Bash; ScopeLens itself also works on Windows and macOS. Preparing, inspecting, and reviewing a workspace reads local evidence without contacting targets or executing collected scripts.

## Install both tools together

Use sibling checkouts and one virtual environment:

```bash
git clone https://github.com/Zendeni/htb-init.git
git clone https://github.com/Zendeni/scopelens.git
python3 -m venv .venv
source .venv/bin/activate
python -m pip install ./scopelens
scopelens --version
scopelens doctor
```

Activate this environment in each new terminal before using the analysis commands. The shell entrypoints use `python3`; set `HTB_PYTHON` to another Python executable if needed. Installing ScopeLens requires access to its source and Python build dependencies; the installed analyzer makes no network requests.

## Review an existing workspace

Prepare the workspace once, including workspaces created by earlier htb-init versions:

```bash
scopelens prepare /path/to/htb-workspace
cd /path/to/htb-workspace
./inspect.sh
./analyze.sh
```

Open the `report.html` path printed by the review command in your browser. Each run gets its own directory under `reports/`, containing `report.html`, `report.json`, and `report.md`. Search or filter the HTML findings, expand their evidence, and check import coverage before drawing conclusions.

After adding or updating your collected artifacts:

```bash
./analyze.sh --baseline latest
```

This compares against the latest eligible saved report. Run an initial review first: `--baseline latest` fails if there is no previous report. You can also pass an explicit baseline with `--baseline /path/to/report.json`.

The equivalent commands work without Bash:

```console
scopelens inspect /path/to/htb-workspace
scopelens review /path/to/htb-workspace
scopelens review /path/to/htb-workspace --baseline latest
```

You can also use the htb-init entrypoint:

```bash
bash htb-init/htb-init.sh --prepare /path/to/htb-workspace
bash htb-init/htb-init.sh --inspect /path/to/htb-workspace --json
bash htb-init/htb-init.sh --review /path/to/htb-workspace
bash htb-init/htb-init.sh --doctor
bash htb-init/htb-init.sh --rules
```

These commands use the installed ScopeLens package. `--doctor` shows the selected runtime and capabilities; `--rules` lists its review rules. The adapter keeps argument values and ScopeLens exit codes intact and ignores Python modules in the current workspace.

## Create a new workspace

From the directory containing both checkouts, with the environment active:

```bash
bash htb-init/htb-init.sh example 192.0.2.10
cd "$HOME/htb_labs/example"
./inspect.sh
```

Use a short box name without `.htb`. New workspaces default to `$HOME/htb_labs/<box>`. To choose another root:

```bash
HTB_LABS_ROOT="$HOME/assessments" bash htb-init/htb-init.sh example 192.0.2.10
```

When a compatible ScopeLens installation is available, the initializer prepares the offline analysis helpers automatically. Otherwise it prints installation and preparation guidance; run `scopelens prepare /path/to/htb-workspace` after installing ScopeLens.

The initializer creates a workspace and supporting scripts. The new integration does not run those collection scripts. Add already collected artifacts to `scans/` and `enum/`, then inspect and review the workspace.

## One-launch reconnaissance and vulnerability intelligence

The generated collector runs the complete reconnaissance workflow with one
command:

```bash
./recon.sh
```

After collection, the bundled analyzer always writes **`overview.md`** with up
to three evidence-backed attack paths, the next test for each, and important
coverage gaps. Start there. `overview.json` contains the same structured
decisions; `recon-analysis.md` retains the supporting detail. Online OSV/NVD
enrichment adds version-based research candidates. Broad Nuclei, Nikto, legacy
enum4linux, and the Nmap `vuln` category are deep-mode checks rather than
standard-mode defaults. Every external network scanner has a time ceiling. A
timed-out command receives `TERM`, then `KILL` after ten seconds, and the next
stage continues. Stage updates include percentage and elapsed time.

Standard mode keeps the high-signal discovery and protocol enumeration:

```bash
./recon.sh
```

Deep mode restores the broad checks for a deliberately thorough run:

```bash
RECON_DEEP=1 ./recon.sh
```

The individual switches remain available: `WEB_ASSESS`, `NUCLEI_ENABLE`,
`NIKTO_ENABLE`, `VULN_SCAN`, and `MQTT_ALL_TOPICS`.

The main safety limits (in seconds) are `NMAP_MAXTIME=900`,
`SERVICE_ENUM_MAXTIME=300`, `WEB_PROBE_MAXTIME=120`, `FEROX_MAXTIME=240`,
`FFUF_MAXTIME=180`, `NIKTO_MAXTIME=600`, `NUCLEI_MAXTIME=600`,
`MQTT_ENUM_MAXTIME=30`, `WEB_ASSESS_MAXTIME=2100`, `ANALYZER_MAXTIME=900`, and
`ARCHIVE_MAXTIME=300`. Override any of them for one run, for example:

```bash
NMAP_MAXTIME=600 NIKTO_MAXTIME=300 NUCLEI_MAXTIME=300 ./recon.sh
```

The scope-aware broad web assessment described below is opt-in and enabled by
`RECON_DEEP=1`. When explicitly enabled on an Active Directory controller, it
is deferred until SMB, MSRPC, LDAP, Kerberos, and WinRM enumeration has run.
Its crawler and Nuclei stages are internally bounded, with an outer hard
deadline:

```bash
WEB_ASSESS=1 ./recon.sh
WEB_ASSESS_MAXTIME=2100 ./recon.sh
WEB_ASSESS=0 ./recon.sh
```

Windows and Active Directory detection is additive; generic and Linux targets
retain the normal stage order. A detected AD target writes normalized facts to
`scans/target-profile.txt` and `enum/windows/profile.txt`, records clock-skew
and NTP query evidence without changing local time, queries LDAP rootDSE, and
adds target-bound MSRPC checks. Kerberos username enumeration is intrusive and
disabled unless both a realm and user list are supplied explicitly:

```bash
KERBEROS_REALM=EXAMPLE.HTB KERBEROS_USERDB=/path/to/users.txt ./recon.sh
```

NSE category scans exclude broadcast scripts, and DNS enumeration remains
pinned to the configured target resolver. Discovered alternate addresses are
evidence only; the collector does not scan them automatically.

MQTT on port 1883 receives a bounded, read-only `$SYS/#` subscription when
`mosquitto_sub` is installed. Subscribing to all application topics remains a
deep-mode or explicit action; the collector never publishes MQTT messages.

```bash
MQTT_ALL_TOPICS=1 MQTT_ENUM_MAXTIME=120 ./recon.sh
```

Each run starts with clean `scans/` and `enum/` evidence. Previous generated
evidence and logs are moved into `runs/` rather than deleted. The current run
writes `run-status.json` and `run-stages.tsv`, and the final archive contains
only current-run evidence.

At startup, the collector refreshes Nuclei templates only when Nuclei or the
broad web assessment is enabled, and rebuilds Nmap's local NSE script index.
The preflight is bounded and can be disabled for a repeatable offline run:

```bash
UPDATE_SCANNER_DATA=0 ./recon.sh
```

The collector deliberately does not upgrade scanner binaries or operating-system
packages; manage those separately with the host's package manager.

Online enrichment is enabled by default. Disable the analyzer's API lookups
while retaining the local evidence analysis and overview:

```bash
ONLINE_VULN_CHECK=0 ./recon.sh
```

Online matches are research leads, not proof of exploitability. Distribution
backports, broad product matches, and incomplete version fingerprints can all
produce false positives.

The overview distinguishes scanner matches from version-based candidates and
does not promote a product name or an unexecuted template to a vulnerability.
Routes retain the affected endpoint, source evidence, confidence, prerequisites
and a concrete verification step. A partial scan is reported as partial, even
when the scanners that finished returned no findings.

Before a new collection starts, preflight checks run without changing previous
evidence. A successful start archives the previous collection under `runs/`
and creates fresh `scans/` and `enum/` directories. `run-status.json` and
`run-stages.tsv` record command outcomes, including failures and timeouts.
Concurrent collectors in the same workspace are rejected.

Vhost namespace discovery accepts HTB-style suffixes (`htb`, `vl`, and
`local`) by default so external links found in page content are not fuzzed as
target namespaces. Extend the list when a lab uses another suffix:

```bash
VHOST_SUFFIXES=htb,vl,local,test ./recon.sh
```

## Windows HTB targets from Kali

Use the same `htb-init.sh <box> <ip>` and `./recon.sh` workflow for Windows
targets. The collector selects SMB, LDAP/LDAPS, Kerberos, WinRM, RDP and MSSQL
enumeration from discovered ports and service fingerprints. It saves Nmap XML
alongside readable output so domain names, hostnames, access results and
vulnerability matches retain their source evidence. RDP and MSSQL checks gather
service/NTLM information; LDAPS-only targets are queried on their actual TLS port.

The short overview prioritizes explicit vulnerability matches and observed
access, such as an anonymously readable SMB share or directory objects returned
without credentials. A share name, an open RDP/WinRM port or public LDAP RootDSE
metadata alone is not a vulnerability. SMB signing observations are conditional
research leads with prerequisites, not proof that relay will work. Windows
build numbers also do not establish missing security patches.

Web applications on Windows use the same scoped HTTP and session-aware input
testing. This supports scanning Windows targets **from Kali/Linux**; the full
collector still requires Bash and its external Linux reconnaissance tools.

## Files you will use

| File or directory | Purpose |
| --- | --- |
| `.target.env` | Workspace metadata; ScopeLens reads literal values as text |
| `scope.json` | Explicit included and excluded IP addresses, networks, and hostnames |
| `analyze.sh` | Run an offline review with a fresh output directory |
| `inspect.sh` | Inspect artifact coverage and saved reports |
| `ANALYSIS.md` | Local instructions for the shared analysis workflow |
| `tools/analyze-recon.py` | Bundled legacy analyzer used for automatic OSV/NVD enrichment |
| `overview.md`, `overview.json` | Short, ranked attack paths and coverage gaps; read these first |
| `recon-analysis.md` | Detailed local evidence analysis and optional vulnerability intelligence |
| `run-status.json`, `run-stages.tsv` | Current collection identity, command outcomes and completion status |
| `runs/` | Previous collections, preserved before fresh scans start |
| `web-assess.sh`, `web-assess.py` | Scope-aware HTTP templates and session-aware request/input testing |
| `enum/web/assessments/` | Separate web-assessment reports, findings, inventories, and stage logs |
| `scans/`, `enum/` | Existing collected artifacts |
| `reports/` | Separate review snapshots; excluded from subsequent evidence imports |
| `notes.md`, `writeup.md` | Your working notes and final writeup |

Preparation preserves existing scope and custom files. It derives initial scope entries from literal `IP` and `HOST` values in `.target.env`; it never sources that file. Review `scope.json` before analysis, particularly when your evidence uses additional hostnames. IP and DNS names are matched independently without DNS resolution.

```json
{
  "include": ["192.0.2.10", "example.htb"],
  "exclude": []
}
```

Exclusions take priority. An empty include list admits observed host identifiers except explicit exclusions and produces a warning. A scope file filters evidence; it does not establish authorization.

## Inspect and automate

```console
scopelens inspect /path/to/htb-workspace --json
scopelens review /path/to/htb-workspace --fail-on medium
scopelens review /path/to/htb-workspace --format json
scopelens rules
```

Inspection reads the workspace without creating a report. Its loaded file count means readable artifacts; the analysis report separately shows which artifacts were parsed. Review requires a scope file, defaulting to `scope.json`, and always writes to a new report directory. Use `--scope` or `--output` to choose explicit paths. `--fail-on` returns exit code `1` when a finding reaches the selected severity, after saving reports. Exit code `2` indicates invalid input or another error; an analysis with no observations also returns `2` and saves coverage diagnostics. Review the diagnostics even when the exit code is `0`.

For an existing ZIP archive or a single supported artifact, use the explicit analysis command:

```console
scopelens analyze /path/to/recon.zip -o /path/to/new-review --scope /path/to/scope.json
```

`analyze` requires a new output directory and uses a scope file only when you supply `--scope`. ZIP contents are read in place, without extraction or execution.

## Compatibility and limits

ScopeLens supports existing Nmap XML/text, httpx JSONL/text, saved HTTP headers, ffuf JSON, npm lockfiles, and pinned Python requirements. Other artifacts may remain useful for manual inspection without having a dedicated parser. See the [shared compatibility guide](https://github.com/Zendeni/scopelens/blob/main/docs/compatibility.md) for supported fields, limits, and diagnostics.

Reports retain source locations and hashes, and redact common secret patterns. Redaction is best effort: review reports before sharing. Raw workspace archives preserve original evidence and can contain sensitive material. Analysis reports are stored separately and are not automatically included in those archives.

Changes between reports describe differences in supplied evidence. A removed finding can reflect changed collection or parser coverage and does not by itself prove remediation.

## Web application assessment

New workspaces include `web-assess.sh` and `web-assess.py`. Use the full checkout
when initializing: the Python helper must sit beside `htb-init.sh` to be copied.
Existing workspaces can use `python3 /path/to/htb-init/web-assess.py --workspace /path/to/workspace`.
This is an **active** collection step, separate from offline ScopeLens review.
`recon.sh` starts it only in deep mode or when `WEB_ASSESS=1` is supplied.

Install [ProjectDiscovery Nuclei](https://docs.projectdiscovery.io/opensource/nuclei/install)
and its signed community templates before running the collector:

```bash
nuclei -version
nuclei -update-templates
# The helper auto-detects ~/.local/nuclei-templates or ~/nuclei-templates;
# override with --templates or NUCLEI_TEMPLATES.
./web-assess.sh --dry-run
./web-assess.sh
```

The script reads `enum/web/live-web-urls.txt` and
`enum/web/discovered-host-web-urls.txt`, validates explicit scope, performs a
bounded same-origin HTML crawl, and runs two distinct Nuclei stages:

- Signed HTTP templates for known XSS, XXE, SSRF, CVEs, exposed files, CORS,
  misconfiguration and other checks present in the installed template set.
- DAST templates against discovered query inputs, usable GET/POST forms, and
  captured requests. The helper preserves request methods, bodies, cookies and
  exact-origin authentication, and supplies Nuclei's required `-dast` flag.

It saves the selected template inventory, commands, JSONL findings, logs,
`report.json` and `report.md` in a fresh `enum/web/assessments/<run>/` directory.
No templates, missing tools, timeouts, malformed findings and failed stages are
reported as incomplete. Exit codes: `0` completed/planned, `1` findings, `2`
invalid or incomplete assessment, `130` interrupted. A completed run describes
the selected automation only; skipped checks and the manual checklist remain.

```bash
# Review discovered scope before scanning. scope.json exclusions always win.
./web-assess.sh --dry-run
# Include a discovered vhost explicitly; ensure it resolves to the lab IP.
./web-assess.sh --allow-host app.example.htb --url 'http://app.example.htb:8080/'
# Supply parameterized URLs or a newline-delimited endpoint list.
./web-assess.sh --url 'http://example.htb/search?q=test'
./web-assess.sh --urls-file endpoints.txt --no-crawl
# Allow lab self-signed TLS for the crawler; enable blind callback tests.
./web-assess.sh --insecure --oast
# Tune request volume and deadlines.
./web-assess.sh --rate-limit 5 --concurrency 1 --max-pages 20 --scan-timeout 1800
```

For an authenticated application, supply a session file. Authentication is bound
to the exact origin, including scheme and port; it is not reused across vhosts
or redirects. The crawler also preserves cookies issued during navigation.

```json
{
  "origins": {
    "https://example.htb": {
      "headers": {"Authorization": "Bearer REPLACE_WITH_LAB_TOKEN"},
      "cookies": {"session": "REPLACE_WITH_LAB_SESSION"}
    }
  }
}
```

Capture requests for APIs or inputs that navigation cannot discover. A request
file accepts JSON as below, or Burp XML exports. Keep the actual content type,
method and body. All request targets must pass the same explicit scope checks.

```json
{
  "requests": [
    {
      "method": "POST",
      "url": "https://example.htb/api/search",
      "headers": {"Content-Type": "application/json"},
      "body": "{\"query\":\"example\"}"
    }
  ]
}
```

```bash
./web-assess.sh --session-file session.json --requests-file requests.json
# Forward the same inputs through the one-launch collector:
WEB_SESSION_FILE="$PWD/session.json" WEB_REQUESTS_FILE="$PWD/requests.json" ./recon.sh
```

Request inventories can contain session cookies, authorization headers and
hidden form tokens. Keep them local; generated raw request files use owner-only
permissions on Unix. Short overviews omit those values. Static session material
does not implement a login workflow or refresh single-use CSRF tokens: expired
authentication, unsupported forms and untested inputs must be reviewed in the
coverage section.

The DAST stage uses these sessions and captured requests. The separate generic
HTTP-template stage remains unauthenticated. Baseline requests check for denied
access before fuzzing; they can submit POST requests. Approved vhost aliases
must resolve locally: curl `--resolve` mappings from discovery are not inherited
by Nuclei. Unresolvable origins are recorded as incomplete coverage.

`scope.json` is authoritative when present; otherwise literal `IP` and `HOST`
values in `.target.env` establish scope without sourcing shell code. This
collector requires nonempty included scope, unlike the offline evidence filter.
`--allow-host` adds exact names/IPs; wildcard/suffix matching is not implicit.
Automatic URL lists skip excluded/unknown hosts with diagnostics; explicit
out-of-scope inputs fail. Explicit URL options replace the discovery lists.
Redirects are disabled in Nuclei, and the crawler follows only included origins.
Templates are trusted scanner code: this is target filtering, not a network
sandbox. Update your trusted template checkout separately; scans do not request
updates. The generated empty config prevents user defaults changing the plan.

Defaults: 10 requests/second, 2 concurrent templates, 30 crawl pages, 200
endpoints, 120 seconds for crawling, 900 seconds per scan stage. The crawler
follows query navigation and captures forms without submitting them; the active
DAST stage tests usable captured inputs. It does not render JavaScript.
Nuclei handles its own TLS validation behavior; `--insecure`
controls only the Python crawler. `--no-crawl` and `--no-dast` disable those steps.
DoS/brute-force and headless/code checks are excluded. OAST is off by default;
`--oast` enables Interactsh callbacks, including public callback infrastructure.
Blind SSRF/XXE checks need callback connectivity from the target.
Nuclei excludes whole templates that require Interactsh when OAST is disabled;
this can also omit their in-band XXE payloads. The saved template inventory is
the authority for what was selected.

**Coverage is partial, never a full OWASP certification.** Each report contains
an [OWASP Top 10:2025](https://owasp.org/Top10/2025/) manual checklist. Known XXE
templates can test specific products, but arbitrary XML bodies need captured
requests and compatible templates; a body being captured does not establish
that every injection class was exercised. Stored/DOM XSS,
authenticated authorization/IDOR, session logic, business rules, supply-chain
integrity, cryptography at rest and server-side logging need additional review.
Use Burp/ZAP with representative requests/accounts for those paths. The report
keeps these gaps visible even when no automated finding is returned.

## Earlier workflow

The existing collection scripts and `analyze-recon.py` remain available. ScopeLens is the shared reporting path described above. The [original workflow documentation](docs/legacy-workflow.md) is retained as a historical reference for existing users; its analyzer and command options are separate from ScopeLens.

For ScopeLens development and verification, see its [README](https://github.com/Zendeni/scopelens#development) and [architecture](https://github.com/Zendeni/scopelens/blob/main/docs/architecture.md).

## Maintaining the integration

The offline adapter at the top of `htb-init.sh` owns interpreter selection, dependency checks, command dispatch, and optional preparation after initialization. It is kept in the entrypoint so a copied script remains usable. ScopeLens owns artifact parsing, scope, findings, and report generation; this repository delegates those operations to its installed package.

From this checkout, with ScopeLens installed in the active environment:

```bash
bash -n htb-init.sh
python -m unittest discover -s tests -v
```

The integration tests exercise preparation, inspection, reporting, threshold and error statuses, copied entrypoints, and untrusted metadata using synthetic local artifacts. CI installs a pinned ScopeLens revision so the tested pairing is explicit. When changing the shared interface, test both repositories and update that pin together.

Collector regressions run generated scripts with mock scanners and online
enrichment disabled. For a separate acceptance test using the real Nuclei
engine and a local trusted template checkout:

```bash
python tests/run_nuclei_acceptance.py \
  --nuclei /path/to/nuclei --templates /path/to/nuclei-templates \
  --output /tmp/htb-acceptance
```

This starts disposable loopback fixtures, tests cookie-preserving navigation,
POST forms with hidden CSRF fields, authenticated JSON/XML requests, positive
and negative injection responses, unreachable-target reporting, and the final
attack-path report. It uses signed templates already present locally, disables
updates and OAST, and does not scan a real lab target.
