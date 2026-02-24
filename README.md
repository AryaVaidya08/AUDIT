# AUDIT

Local-first repository security scanner with deterministic fallback findings when no LLM API key is configured.

## Quickstart

Use these exact commands from a fresh clone:

```bash
cd /path/to/AUDIT
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
cd demo_vuln_repo
audit-code . --out report.json
```

Keep the virtual environment activated so `audit-code` resolves to the local editable install and not the macOS system `audit` binary.

## What you should see

`audit-code` writes a full JSON report to the path given by `--out` (default: `report.json` in the current directory) and prints a readable summary to stdout.

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

### Commands

| Command | Description |
|---|---|
| `audit-code [PATH]` | Scan a repository (default command, PATH defaults to `.`) |
| `audit-code scan [PATH]` | Explicit form of the scan command |
| `audit-code help` | Print full usage reference |

### Core options

| Flag | Description | Default |
|---|---|---|
| `--out PATH` | Where to write the full JSON report | `report.json` |
| `--fail-on SEVERITY` | Exit `1` if any finding meets/exceeds this level (`low\|medium\|high\|critical`) | off |
| `--model NAME` | LLM model name to use for analysis | env default |
| `--progress / --no-progress` | Stream per-chunk progress to stderr | on |

### Scan tuning

| Flag | Description |
|---|---|
| `--top-k INT` | KB documents retrieved per code chunk (min 1) |
| `--threshold FLOAT` | Minimum similarity score for a KB doc to be used (0.0–1.0) |
| `--max-chunks INT` | Cap on total chunks analysed (min 1) |
| `--chunk-size-lines INT` | Lines of code per chunk sent to the LLM (min 1) |
| `--llm-timeout-seconds FLOAT` | Per-call LLM timeout in seconds (min 1.0) |
| `--repair-retries INT` | Retries on malformed LLM JSON responses (min 0) |

### Prefilter options

| Flag | Description |
|---|---|
| `--prefilter-min-score FLOAT` | Discard chunks below this heuristic score (0.0–1.0) |
| `--prefilter-max-candidates INT` | Max chunks forwarded to LLM/cache after pre-filtering (min 1) |

### Concurrency

| Flag | Description |
|---|---|
| `--max-inflight-llm-calls INT` | Maximum concurrent LLM requests in flight (min 1) |

### Caching

AUDIT can cache chunk-level results so repeated scans of unchanged code run faster. Cache hits reuse prior findings; cache misses are rescanned. AUDIT does not modify any files in the scanned repository.

| Flag | Description | Default |
|---|---|---|
| `--cache / --no-cache` | Enable or disable the incremental SQLite cache | on |
| `--cache-scope user\|repo` | Where the cache file lives when `--cache-path` is not set | `user` |
| `--cache-path PATH` | Explicit path to the SQLite cache file | — |

`--cache-scope user` places the cache in a shared location reused across all repos.
`--cache-scope repo` stores the cache inside the scanned repo at `.audit/scan_cache.sqlite3`.

### Resume / checkpoint

| Flag | Description |
|---|---|
| `--resume / --no-resume` | Resume from a matching checkpoint when available |
| `--checkpoint-path PATH` | Path to the checkpoint JSON file |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed (findings may still exist) |
| `1` | Scan completed and `--fail-on` threshold was met |
| `2` | Argument, config, or runtime error |

## Examples

```bash
# Scan current directory, write report to report.json
audit-code .

# Scan a specific repo, save report to a custom path
audit-code /path/to/repo --out /tmp/my-report.json

# Fail CI if any high or critical findings are found
audit-code . --fail-on high

# Resume an interrupted scan with caching enabled
audit-code . --resume --cache

# Disable progress output and limit concurrency
audit-code . --no-progress --max-inflight-llm-calls 2

# Print full usage reference
audit-code help
```

## CI example

```bash
python -m pip install -e .
audit-code . --out report.json --fail-on high
```

This keeps CI green for low/medium-only findings and fails when high/critical findings are present.
