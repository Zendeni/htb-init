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

Its vulnerability stage enables Nmap service detection before the `vuln`
script category, allowing version-dependent scripts such as Vulners to query
current online intelligence. After collection, the bundled legacy analyzer
queries OSV and NVD for detected packages and technologies and writes
`recon-analysis.md`. Nuclei and Nikto continue to provide template-based web
checks. Every external network scanner has a time ceiling. A
timed-out command receives `TERM`, then `KILL` after ten seconds, and the next
stage continues. Stage updates include percentage and elapsed time.

The main safety limits (in seconds) are `NMAP_MAXTIME=900`,
`SERVICE_ENUM_MAXTIME=300`, `WEB_PROBE_MAXTIME=120`, `FEROX_MAXTIME=240`,
`FFUF_MAXTIME=180`, `NIKTO_MAXTIME=600`, `NUCLEI_MAXTIME=600`,
`WEB_ASSESS_MAXTIME=2100`, `ANALYZER_MAXTIME=900`, and
`ARCHIVE_MAXTIME=300`. Override any of them for one run, for example:

```bash
NMAP_MAXTIME=600 NIKTO_MAXTIME=300 NUCLEI_MAXTIME=300 ./recon.sh
```

When a web application is found, the scope-aware web assessment described
below runs automatically after hostname discovery. Its crawler and two Nuclei
stages are internally bounded, and the collector also applies an outer hard
deadline. Disable it independently when only basic reconnaissance is wanted:

```bash
WEB_ASSESS_MAXTIME=2100 ./recon.sh
WEB_ASSESS=0 ./recon.sh
```

At startup, the collector refreshes Nuclei templates and rebuilds Nmap's local
NSE script index. Nikto performs its own built-in update check when scanning.
The preflight is bounded and can be disabled for a repeatable offline run:

```bash
UPDATE_SCANNER_DATA=0 ./recon.sh
```

The collector deliberately does not upgrade scanner binaries or operating-system
packages; manage those separately with the host's package manager.

Online enrichment is enabled by default. Disable it for an offline collection:

```bash
ONLINE_VULN_CHECK=0 ./recon.sh
```

Online matches are research leads, not proof of exploitability. Distribution
backports, broad product matches, and incomplete version fingerprints can all
produce false positives.

Vhost namespace discovery accepts HTB-style suffixes (`htb`, `vl`, and
`local`) by default so external links found in page content are not fuzzed as
target namespaces. Extend the list when a lab uses another suffix:

```bash
VHOST_SUFFIXES=htb,vl,local,test ./recon.sh
```

## Files you will use

| File or directory | Purpose |
| --- | --- |
| `.target.env` | Workspace metadata; ScopeLens reads literal values as text |
| `scope.json` | Explicit included and excluded IP addresses, networks, and hostnames |
| `analyze.sh` | Run an offline review with a fresh output directory |
| `inspect.sh` | Inspect artifact coverage and saved reports |
| `ANALYSIS.md` | Local instructions for the shared analysis workflow |
| `tools/analyze-recon.py` | Bundled legacy analyzer used for automatic OSV/NVD enrichment |
| `recon-analysis.md` | Online vulnerability-intelligence report produced by `recon.sh` |
| `web-assess.sh`, `web-assess.py` | Scope-aware active HTTP template and query-parameter DAST workflow |
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
Running `recon.sh` starts it after web/vhost discovery; `WEB_ASSESS=0` disables it.

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
- DAST templates against query parameters discovered in links and GET forms,
  or supplied in an endpoint list. DAST must be enabled explicitly in Nuclei;
  the helper supplies `-dast` automatically.

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
does not submit forms or render JavaScript; discovered query endpoints are
passed to DAST. Nuclei handles its own TLS validation behavior; `--insecure`
controls only the Python crawler. `--no-crawl` and `--no-dast` disable those steps.
DoS/brute-force and headless/code checks are excluded. OAST is off by default;
`--oast` enables Interactsh callbacks, including public callback infrastructure.
Blind SSRF/XXE checks need callback connectivity from the target.

**Coverage is partial, never a full OWASP certification.** Each report contains
an [OWASP Top 10:2025](https://owasp.org/Top10/2025/) manual checklist. Known XXE
templates can test specific products, but arbitrary XML bodies need captured
requests and parser-specific testing. POST/JSON body fuzzing, stored/DOM XSS,
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

The integration tests exercise preparation, inspection, reporting, threshold and error statuses, copied entrypoints, and untrusted metadata using synthetic local artifacts. They do not run collection. CI installs a pinned ScopeLens revision so the tested pairing is explicit. When changing the shared interface, test both repositories and update that pin together.
