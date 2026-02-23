# AUDIT

Local-first repository security scanner with deterministic fallback findings when no LLM API key is configured.

## Quickstart

Use these exact commands from a fresh clone:

```bash
cd /Users/admin/Downloads/AUDIT
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
cd demo_vuln_repo
audit . --out report.json
```

Important: keep the virtual environment activated so `audit` resolves to the local editable install.

## What you should see

`audit` writes a full JSON report file and prints a readable summary.

Example output:

```text
Severity counts: critical=0, high=5, medium=0, low=0
Top findings (up to 5):
1. [high] routes.js:4 AUTH.MISSING_ADMIN_GUARD - Privileged route may be missing an auth check
2. [high] vuln_app.py:4 SECRET.HARDCODED_ASSIGNMENT - Hardcoded secret assignment
3. [high] vuln_app.py:8 SQLI.DYNAMIC_QUERY - Potential SQL injection via dynamic query
4. [high] vuln_app.py:14 CODE_EXEC.DYNAMIC_EVAL - Dynamic code execution with eval/exec
5. [high] vuln_app.py:18 DESERIALIZE.UNSAFE_LOAD - Unsafe deserialization call
Full report: /absolute/path/to/demo_vuln_repo/report.json
```

## CLI

Default behavior:

```bash
audit . --out report.json
```

Explicit subcommand (same scan logic):

```bash
audit scan . --out report.json
```

Common flags:

- `--out PATH`: write full JSON report (default: `report.json` in the current directory)
- `--fail-on {low|medium|high|critical}`: exit `1` when any finding meets/exceeds the threshold
- `--progress/--no-progress`: show per-chunk progress on stderr
- advanced scan tuning flags are also available (`--top-k`, `--threshold`, `--max-chunks`, cache/resume flags, etc.)

Exit codes:

- `0`: scan completed (even if findings exist)
- `1`: scan completed and `--fail-on` threshold was met
- `2`: argument/config/runtime error

## Caching (plain terms)

- AUDIT can cache chunk-level results so repeated scans of unchanged code run faster.
- Cache hits reuse prior findings; cache misses are rescanned.
- You can disable cache with `--no-cache` or switch cache location with `--cache-scope` / `--cache-path`.

## Safety

AUDIT does not modify code in the scanned repository. It only reads files and writes report/cache artifacts.

## CI example

```bash
python -m pip install -e .
audit . --out report.json --fail-on high
```

This keeps CI green for low/medium-only findings and fails when high/critical findings are present.