from __future__ import annotations

import logging
import re
from pathlib import Path

from fastapi import FastAPI, HTTPException

from app.config import settings
from app.embed.embeddings import TextEmbedder
from app.ingest.repo_loader import collect_files
from app.parse.chunkers import chunk_sources
from app.scan.kb_loader import load_kb_documents
from app.scan.scan_repo import scan_repo as run_scan_repo
from app.scan.schema import IndexReport, IndexRequest, RetrievalSample, ScanReport, ScanRequest, SourceFile
from app.vectorstore.chroma_store import ChromaCollections, ChromaStore

app = FastAPI(title="AUDIT")
logger = logging.getLogger("audit")
PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SUSPICIOUS_QUERY_PATTERN = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|AKIA[0-9A-Z]{16}|select|insert|update|delete|execute\(|query\()"
)
_TEXT_HEAVY_SUFFIXES = (".md", ".txt", ".rst")


@app.get("/")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanReport)
def scan_local_repo(payload: ScanRequest) -> ScanReport:
    repo_path = Path(payload.local_path).expanduser().resolve()
    if not repo_path.exists():
        raise HTTPException(status_code=404, detail="local_path does not exist")
    if not repo_path.is_dir():
        raise HTTPException(status_code=400, detail="local_path must be a directory")
    try:
        return run_scan_repo(
            path=repo_path,
            top_k=settings.scan_top_k,
            threshold=settings.scan_similarity_threshold,
            max_chunks=settings.scan_max_chunks,
            repair_retries=settings.scan_repair_retries,
            model=settings.scan_model,
            chunk_size_lines=settings.chunk_size_lines,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except NotADirectoryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _resolve_from_project(raw_path: str) -> Path:
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    return candidate.resolve()


@app.post("/index", response_model=IndexReport)
def index_local_repo(payload: IndexRequest) -> IndexReport:
    repo_path = Path(payload.local_path).expanduser().resolve()
    if not repo_path.exists():
        raise HTTPException(status_code=404, detail="local_path does not exist")
    if not repo_path.is_dir():
        raise HTTPException(status_code=400, detail="local_path must be a directory")

    kb_dir = _resolve_from_project(settings.kb_dir)
    persist_dir = _resolve_from_project(settings.chroma_persist_dir)
    persist_dir.mkdir(parents=True, exist_ok=True)

    try:
        kb_docs = load_kb_documents(kb_dir)
    except (FileNotFoundError, NotADirectoryError, ValueError) as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    raw_files = collect_files(root=repo_path)
    source_files = [SourceFile(**item) for item in raw_files]
    chunks = chunk_sources(source_files, chunk_size_lines=settings.chunk_size_lines)

    embedder = TextEmbedder(model=settings.embedding_model, batch_size=settings.embedding_batch_size)
    try:
        store = ChromaStore(
            persist_dir=str(persist_dir),
            collections=ChromaCollections(
                code_chunks=settings.chroma_collection_code_chunks,
                security_kb=settings.chroma_collection_security_kb,
            ),
            embedder=embedder,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    kb_docs_indexed = store.upsert_kb_documents(kb_docs)
    code_chunks_indexed = store.upsert_code_chunks(chunks)

    suspicious_chunks = [
        chunk
        for chunk in chunks
        if not chunk.file_path.lower().endswith(_TEXT_HEAVY_SUFFIXES)
        and _SUSPICIOUS_QUERY_PATTERN.search(chunk.text)
    ]
    if suspicious_chunks:
        query_candidates = suspicious_chunks[:1]
    else:
        non_docs = [chunk for chunk in chunks if not chunk.file_path.lower().endswith(_TEXT_HEAVY_SUFFIXES)]
        query_candidates = non_docs[:1] if non_docs else chunks[:1]
    top_k = payload.top_k or settings.retrieval_top_k
    retrieval_samples: list[RetrievalSample] = []

    for chunk in query_candidates:
        hits = store.query_security_kb(query_text=chunk.text, top_k=top_k)
        sample = RetrievalSample(
            file_path=chunk.file_path,
            start_line=chunk.start_line,
            end_line=chunk.end_line,
            hits=hits,
        )
        retrieval_samples.append(sample)
        if settings.debug_retrieval:
            summary = ", ".join([f"{hit.id}:{hit.score:.3f}" for hit in hits])
            print(f"DEBUG_RETRIEVAL file={chunk.file_path} lines={chunk.start_line}-{chunk.end_line} hits=[{summary}]")
            logger.info(
                "retrieval_test file=%s lines=%s-%s top_hits=[%s]",
                chunk.file_path,
                chunk.start_line,
                chunk.end_line,
                summary,
            )

    return IndexReport(
        kb_docs_indexed=kb_docs_indexed,
        code_chunks_indexed=code_chunks_indexed,
        retrieval_samples=retrieval_samples,
        persist_dir=str(persist_dir),
    )
