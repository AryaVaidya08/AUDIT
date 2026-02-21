# AUDIT - Day 3 Scan Engine

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

## Run Local Scan (No Server)

From the repository root, run:

```bash
python -m audit.scan_repo
```

By default, this scans `test_repo/`. You can also pass an explicit path.

Optional flags:

```bash
python -m audit.scan_repo ./demo_vuln_repo \
  --top-k 5 \
  --threshold 0.2 \
  --max-chunks 300 \
  --repair-retries 1 \
  --model gpt-4.1-mini
```

The command always returns a valid JSON `ScanReport`:
- `metadata` (model/config/runtime)
- `stats` (`files_scanned`, `chunks_considered`, `llm_calls`, `skipped_low_similarity`, parse/skip counters)
- `findings[]`
- `errors[]` (chunk-level graceful failures)

## Reliability Guarantees

- LLM output is JSON-enforced.
- If output is non-JSON, one repair retry is attempted.
- If retry still fails, that chunk is skipped and logged in `errors`.
- The overall scan continues and returns a valid report object.
- Findings are normalized and deduplicated by `(file_path, start_line, vuln_type)`.

## Run API (Optional)

From repository root:

```bash
cd backend
uvicorn app.main:app --reload
```

Health check:

```bash
curl http://127.0.0.1:8000/
```

Expected response:

```json
{"status":"ok"}
```

## API Scan Endpoint

```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"local_path":"/absolute/path/to/repo"}'
```

The endpoint now calls the same `scan_repo(...)` core flow used by `python -m audit.scan_repo`.

## Index for Retrieval (Day 2)

`POST /index` indexes:
- KB markdown docs (`backend/app/scan/kb/*.md`) into `security_kb`
- repo code chunks into `code_chunks`

It writes a persistent Chroma DB in `.chroma/` by default.

```bash
curl -X POST http://127.0.0.1:8000/index \
  -H "Content-Type: application/json" \
  -d '{"local_path":"/absolute/path/to/repo","top_k":5}'
```

Response includes:
- `kb_docs_indexed`
- `code_chunks_indexed`
- `retrieval_samples` (top KB hits + scores for a suspicious code chunk)
- `persist_dir`

## Notes

- Files are chunked into 120-line blocks by default.
- Include/exclude behavior and limits are configurable via environment variables in `.env.example`.
- The app auto-loads repo-root `.env` and `.env.local` values on startup.
- If `OPENAI_API_KEY` is missing, embeddings fall back to deterministic local vectors and LLM audit calls are skipped gracefully.

## Scan Environment Variables

See `.env.example` for defaults:

- `SCAN_MODEL`
- `SCAN_TOP_K`
- `SCAN_SIMILARITY_THRESHOLD`
- `SCAN_MAX_CHUNKS`
- `SCAN_REPAIR_RETRIES`
