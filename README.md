# AUDIT

**Local-first security scanner for source code repositories.**

## Why AUDIT?

AUDIT combines LLM-powered analysis with a curated 49-pattern knowledge base to find real vulnerabilities in your code (not just lint warnings). It runs locally, caches results incrementally so rescans are fast, and produces machine-readable JSON reports that slot straight into CI pipelines. When the LLM is unavailable, a heuristic prefilter still catches the obvious issues.

## Feature Highlights

- **AI-powered analysis**: each code chunk is evaluated by an LLM with retrieval-augmented context from the knowledge base
- **49-pattern knowledge base**: covers 12 vulnerability categories mapped to CWE and OWASP Top 10
- **Heuristic prefilter**: scores chunks before LLM calls to skip irrelevant code and cut costs
- **Incremental caching**: SQLite cache keyed on content hash; unchanged code is never re-scanned
- **Resume/checkpoint**: interrupted scans pick up where they left off
- **Resilient**: rate-limit retries with exponential backoff; transient connectivity failures are warnings, not hard errors
- **Cross-platform**: prebuilt binaries for macOS (ARM + x64), Linux x64, and Windows x64
- **CI-ready**: `--fail-on` exit codes, JSON output, and `--no-progress` for clean logs

## What It Detects

AUDIT’s knowledge base covers 12 vulnerability categories:

| # | Category | Patterns |
|---|----------|----------|
| 1 | Injection (SQL, command, template, NoSQL, LDAP, XPath, header, log, expression language) | 9 |
| 2 | Authentication & Session (JWT, OAuth, MFA bypass, session fixation) | 5 |
| 3 | Authorization & Access Control (CSRF, IDOR, mass assignment) | 3 |
| 4 | Crypto & Secrets (hardcoded creds, API key exposure, weak crypto) | 4 |
| 5 | Input/Output & Web (XSS, SSRF, XXE, open redirect, request smuggling, GraphQL) | 7 |
| 6 | Filesystem & OS (path traversal, zip slip, insecure upload) | 3 |
| 7 | Deserialization & Integrity (insecure deserialization, prototype pollution) | 3 |
| 8 | Dependencies & Supply Chain (dependency confusion, vulnerable deps) | 2 |
| 9 | Config & Deployment (CORS, clickjacking, missing headers, info disclosure) | 6 |
| 10 | Logging & Monitoring (insufficient logging) | 1 |
| 11 | Business Logic (race conditions, ReDoS, type juggling) | 5 |
| 12 | Client-Side (WebSocket hijacking) | 1 |

## Quick Start

```bash
npm i -g audit-code
export OPENAI_API_KEY="your-key"
audit . --out report.json
```

## How It Works

```
source repo
  → file collection & language filtering
    → chunking (configurable line count per chunk)
      → heuristic prefilter (score & rank)
        → KB retrieval (top-k similar patterns per chunk)
          → LLM analysis (with RAG context)
            → incremental cache write
              → JSON report + stdout summary
```

Files are split into chunks, scored by a fast heuristic prefilter, then matched against the knowledge base using similarity search. Each surviving chunk is sent to the LLM along with the most relevant KB patterns as context. Results are cached by content hash so unchanged code is never re-analysed. Scans can be resumed from checkpoints if interrupted.

## Install

### npm global install (no Python required)

```bash
npm i -g audit-code
audit --help
export OPENAI_API_KEY="your-key"
audit . --out report.json
```

The npm package downloads the correct prebuilt binary for your platform during `postinstall` and verifies `sha256` checksums before running it.

### Source install (for development)

```bash
cd /path/to/AUDIT
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[llm,vectorstore]"
export OPENAI_API_KEY="your-key"
audit demo_vuln_repo --out report.json
```

The `llm` extra installs `openai` and the `vectorstore` extra installs `chromadb`.
You can also install them individually (e.g. `pip install -e ".[llm]"`) — see [Optional dependency groups](#optional-dependency-groups) below.

Keep the virtual environment activated so `audit` resolves to the local editable install and not the macOS system `audit` binary.
If your shell still resolves another `audit` binary, use `audit-code ...` (legacy alias) or `python -m audit ...`.

### Optional dependency groups

| Group | Package | Purpose |
|---|---|---|
| `llm` | `openai>=1.0,<2` | Required for LLM-powered analysis |
| `vectorstore` | `chromadb>=0.4,<1` | Enables vector similarity KB retrieval |

Install one or both: `pip install -e ".[llm]"` or `pip install -e ".[llm,vectorstore]"`.

### Runtime requirements

- `OPENAI_API_KEY` must be set for scan commands, otherwise scans exit with code `2`.
- If API key connectivity validation fails at startup (e.g. transient network issue), the scan continues with a warning — per-chunk error handling deals with retries.
- `chromadb` is optional. If Chroma/KB indexing fails, AUDIT falls back to a simpler token-overlap KB retrieval path.
- `.env` and `.env.local` at the repo root are auto-loaded by the backend config module for source runs.

## CLI Reference

### Commands

| Command | Description |
|---|---|
| `audit [PATH]` | Scan a repository (default command, PATH defaults to `.`) |
| `audit scan [PATH]` | Explicit form of the scan command |
| `audit help` | Print full usage reference |
| `audit-code ...` | Legacy alias for `audit ...` |

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
| `--threshold FLOAT` | Minimum similarity score for a KB doc to be used (0.0-1.0) |
| `--max-chunks INT` | Cap on total chunks analysed (min 1) |
| `--chunk-size-lines INT` | Lines of code per chunk sent to the LLM (min 1) |
| `--llm-timeout-seconds FLOAT` | Per-call LLM timeout in seconds (min 1.0) |
| `--repair-retries INT` | Retries when the LLM response fails structured-output validation (min 0) |

### Prefilter options

| Flag | Description |
|---|---|
| `--prefilter-min-score FLOAT` | Discard chunks below this heuristic score (0.0-1.0) |
| `--prefilter-max-candidates INT` | Max chunks forwarded to LLM/cache after pre-filtering (min 1) |

### Concurrency

| Flag | Description |
|---|---|
| `--max-inflight-llm-calls INT` | Maximum concurrent LLM requests in flight (min 1) |

### Caching

AUDIT can cache chunk-level results so repeated scans of unchanged code run faster. Cache hits reuse prior findings; cache misses are rescanned.

| Flag | Description | Default |
|---|---|---|
| `--cache / --no-cache` | Enable or disable the incremental SQLite cache | env default (`SCAN_CACHE_ENABLED`, defaults to on) |
| `--cache-scope user\|repo` | Where the cache file lives when `--cache-path` is not set | `user` |
| `--cache-path PATH` | Explicit path to the SQLite cache file | - |

`--cache-scope user` places the cache in a shared location reused across all repos.
`--cache-scope repo` stores the cache inside the scanned repo at `.audit/scan_cache.sqlite3`.
`--out` controls where the JSON report is written and can also target the scanned repo.

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

## What you should see

`audit` writes a full JSON report to the path given by `--out` (default: `report.json` in the current directory) and prints a readable summary to stdout.

Example summary shape:

```text
Severity counts: critical=<n>, high=<n>, medium=<n>, low=<n>
Top findings (up to 5):
(none)
Full report: /absolute/path/to/report.json
```

Finding counts and individual findings depend on model responses, thresholds, and cache state.

## Examples

```bash
# Scan current directory, write report to report.json
audit .

# Scan a specific repo, save report to a custom path
audit /path/to/repo --out /tmp/my-report.json

# Fail CI if any high or critical findings are found
audit . --fail-on high

# Resume an interrupted scan with caching enabled
audit . --resume --cache

# Disable progress output and limit concurrency
audit . --no-progress --max-inflight-llm-calls 2

# Print full usage reference
audit help
```

## CI example

```bash
python -m pip install -e ".[llm,vectorstore]"
export OPENAI_API_KEY="your-key"
audit . --out report.json --fail-on high
```

This keeps CI green for low/medium-only findings and fails when high/critical findings are present.

## Environment variables

All scan-tuning flags can also be set via environment variables. The most commonly used:

| Variable | Description | Default |
|---|---|---|
| `OPENAI_API_KEY` | OpenAI API key (required for scans) | — |
| `SCAN_MODEL` | LLM model name | `gpt-4.1-mini` |
| `SCAN_TOP_K` | KB documents retrieved per chunk | `5` |
| `SCAN_SIMILARITY_THRESHOLD` | Minimum KB similarity score | `0.2` |
| `SCAN_MAX_CHUNKS` | Max chunks to analyse (`0` = unlimited) | `300` |
| `SCAN_REPAIR_RETRIES` | Retries when the LLM response fails structured-output validation | `1` |
| `SCAN_LLM_TIMEOUT_SECONDS` | Per-call LLM timeout | `20.0` |
| `SCAN_CACHE_ENABLED` | Enable SQLite result cache | `true` |
| `SCAN_CACHE_PATH` | Path to SQLite cache file | `~/Library/Caches/audit/scan_cache.sqlite3` (macOS) |
| `SCAN_MAX_INFLIGHT_LLM_CALLS` | Max concurrent LLM requests | `4` |
| `SCAN_PREFILTER_ENABLED` | Enable heuristic prefilter | `true` |
| `SCAN_PREFILTER_MIN_SCORE` | Minimum prefilter score | `0.2` |
| `SCAN_PREFILTER_MAX_CANDIDATES` | Max candidates after prefilter | `200` |
| `CHUNK_SIZE_LINES` | Lines per code chunk | `120` |
| `KB_SCORE_THRESHOLD` | Minimum KB retrieval score for results | `0.2` |
| `AUDIT_ALLOWED_SCAN_ROOT` | (API server only) Restrict `/scan` and `/index` to paths under this root | current working directory |

## Release artifacts

Each release tag `vX.Y.Z` publishes these binary assets:

- `audit-darwin-arm64`
- `audit-darwin-x64`
- `audit-linux-x64`
- `audit-windows-x64.exe`
- `audit-checksums.txt`

The npm wrapper fetches assets from:

`https://github.com/<owner>/<repo>/releases/download/vX.Y.Z/`

Override this with `AUDIT_BINARY_BASE_URL` when testing mirrors.

## Manual release validation

```bash
npm i -g audit-code@<version>
audit --help
export OPENAI_API_KEY=...
audit . --out report.json
```
