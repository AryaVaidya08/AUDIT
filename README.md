# AUDIT - Day 1 + Day 2 Baseline

Minimal security scanner API with:
- Day 1: heuristic `/scan`
- Day 2: KB + embeddings + Chroma indexing via `/index`

## Project Structure

```text
backend/
  app/
    ingest/
    parse/
    scan/
    utils/
cli/
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install fastapi uvicorn chromadb openai
```

## Run API

From the repository root:

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

## Scan a Local Repo

```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"local_path":"/absolute/path/to/repo"}'
```

The endpoint returns a JSON `ScanReport` with heuristic findings such as:

- hardcoded secrets
- dynamic SQL query construction patterns

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

- Files are chunked into 120-line blocks before scanning.
- Include/exclude behavior and limits are configurable via environment variables in `.env.example`.
- Default embedding model is `text-embedding-3-small`.
- If `OPENAI_API_KEY` is missing, the app falls back to deterministic local embeddings for development.
