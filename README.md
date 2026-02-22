# AUDIT - Day 4 Scan Engine

## Project Structure

```text
backend/
  app/
    ingest/
    parse/
    scan/
    utils/
audit/
cli/
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install fastapi uvicorn chromadb openai pytest
```

## Local Scan (Server Optional)

For local scanning, server startup is not required.

From repository root:

```bash
python -m audit.scan_repo
```

Default target path is `test_repo/`.

## CLI Options

```bash
python -m audit.scan_repo ./test_repo \
  --top-k 5 \
  --threshold 0.2 \
  --max-chunks 300 \
  --repair-retries 1 \
  --llm-timeout-seconds 20 \
  --prefilter-min-score 0.2 \
  --prefilter-max-candidates 200 \
  --max-inflight-llm-calls 4 \
  --cache \
  --cache-path scan_cache.sqlite3 \
  --resume \
  --checkpoint-path scan_resume.json \
  --progress \
  --model gpt-4.1-mini
```

Supported scan flags include:
- `--resume/--no-resume`
- `--prefilter-min-score`
- `--prefilter-max-candidates`
- `--max-inflight-llm-calls`
- `--cache/--no-cache`
- `--cache-path`
- `--checkpoint-path`
- `--llm-timeout-seconds`
- `--progress/--no-progress`

## Scan Pipeline (Single Entrypoint)

Both CLI and API use the same orchestration function: `scan_repo(...)`.

Pipeline order:
1. collect files/chunks
2. compute KB scores + prefilter scores
3. select candidate chunks
4. cache lookup
5. concurrent LLM audit for cache misses
6. merge cached + fresh findings
7. normalize/dedup findings
8. finalize metadata/stats

## Reliability Guarantees

- Output is always a strict `ScanReport` JSON object.
- Chunk-level LLM failures (timeout/parse/network) do not crash the run.
- Findings ordering/dedup is deterministic.
- Per-call LLM timeout is enforced (`SCAN_LLM_TIMEOUT_SECONDS`, `--llm-timeout-seconds`).

## Performance Controls

- Prefilter reduces LLM volume using combined risk score (KB similarity + suspicious pattern hits + extension weight).
- Incremental SQLite cache stores validated `Finding[]` per chunk/model/prompt version.
- Concurrent LLM calls are bounded by `SCAN_MAX_INFLIGHT_LLM_CALLS`.

`stats` now includes:
- `chunks_prefiltered`
- `chunks_sent_to_llm`
- `cache_hits`
- `cache_misses`
- `duration_ms`
- `resume_used`

## Resume Behavior

- Checkpoint file defaults to `scan_resume.json`.
- Resume is enabled with `--resume`.
- Resume applies only when checkpoint run signature matches current scan setup.
- Checkpoints are written periodically (`SCAN_CHECKPOINT_EVERY`) and used to continue long runs.

## API (Optional)

From repository root:

```bash
cd backend
uvicorn app.main:app --reload
```

Health check:

```bash
curl http://127.0.0.1:8000/
```

Scan endpoint:

```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"local_path":"/absolute/path/to/repo"}'
```

`/scan` uses the same `scan_repo(...)` path as local CLI scans.

## Index Endpoint (Optional)

`POST /index` indexes:
- KB markdown docs (`backend/app/scan/kb/*.md`) into `security_kb`
- repo code chunks into `code_chunks`

It persists Chroma data in `.chroma/` by default.

## Environment Variables

See `.env.example` for full defaults. Key scan controls:

- `SCAN_MODEL`
- `SCAN_TOP_K`
- `SCAN_SIMILARITY_THRESHOLD`
- `SCAN_MAX_CHUNKS`
- `SCAN_REPAIR_RETRIES`
- `SCAN_PREFILTER_ENABLED`
- `SCAN_PREFILTER_MIN_SCORE`
- `SCAN_PREFILTER_MAX_CANDIDATES`
- `SCAN_CACHE_ENABLED`
- `SCAN_CACHE_PATH`
- `SCAN_MAX_INFLIGHT_LLM_CALLS`
- `SCAN_CHECKPOINT_PATH`
- `SCAN_CHECKPOINT_EVERY`
- `SCAN_LLM_TIMEOUT_SECONDS`
