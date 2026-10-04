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
```

These commands use the installed ScopeLens package.

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

## Files you will use

| File or directory | Purpose |
| --- | --- |
| `.target.env` | Workspace metadata; ScopeLens reads literal values as text |
| `scope.json` | Explicit included and excluded IP addresses, networks, and hostnames |
| `analyze.sh` | Run an offline review with a fresh output directory |
| `inspect.sh` | Inspect artifact coverage and saved reports |
| `ANALYSIS.md` | Local instructions for the shared analysis workflow |
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

## Earlier workflow

The existing collection scripts and `analyze-recon.py` remain available. ScopeLens is the shared reporting path described above. The [original workflow documentation](docs/legacy-workflow.md) is retained as a historical reference for existing users; its analyzer and command options are separate from ScopeLens.

For ScopeLens development and verification, see its [README](https://github.com/Zendeni/scopelens#development) and [architecture](https://github.com/Zendeni/scopelens/blob/main/docs/architecture.md).
