from __future__ import annotations

from collections.abc import Callable
import logging
from datetime import datetime, timezone
from pathlib import Path

from app.config import settings
from app.embed.embeddings import TextEmbedder
from app.ingest.repo_loader import collect_files
from app.parse.chunkers import chunk_sources
from app.scan.kb_loader import load_kb_documents
from app.scan.llm_audit import audit_chunk_with_llm
from app.scan.schema import (
    CodeChunk,
    Finding,
    RetrievalHit,
    ScanChunkError,
    ScanMetadata,
    ScanReport,
    ScanStats,
    SourceFile,
)
from app.vectorstore.chroma_store import ChromaCollections, ChromaStore

logger = logging.getLogger("audit.scan")
PROJECT_ROOT = Path(__file__).resolve().parents[3]
MAX_REPORTED_ERRORS = 250
_SEVERITY_VALUES = {"low", "medium", "high", "critical"}


def _resolve_from_project(raw_path: str | Path) -> Path:
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    return candidate.resolve()


def _normalize_repo_path(raw_path: str, repo_root: Path) -> str:
    root_text = repo_root.as_posix().rstrip("/")
    value = raw_path.replace("\\", "/").strip()
    if value.startswith(root_text + "/"):
        value = value[len(root_text) + 1 :]
    return value.lstrip("./") or raw_path


def _normalize_severity(raw_value: str) -> str:
    normalized = str(raw_value).strip().lower()
    if normalized in _SEVERITY_VALUES:
        return normalized
    return "medium"


def _clamp_confidence(raw_value: float) -> float:
    return min(max(float(raw_value), 0.0), 1.0)


def _normalize_finding(finding: Finding, repo_root: Path) -> Finding:
    payload = finding.model_dump()
    payload["file_path"] = _normalize_repo_path(payload["file_path"], repo_root)
    payload["severity"] = _normalize_severity(payload["severity"])
    payload["confidence"] = _clamp_confidence(payload["confidence"])
    if payload["end_line"] < payload["start_line"]:
        payload["end_line"] = payload["start_line"]
    return Finding.model_validate(payload)


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    deduped: list[Finding] = []
    seen: set[tuple[str, int, str]] = set()
    for finding in findings:
        key = (finding.file_path, finding.start_line, finding.vuln_type.strip().lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    deduped.sort(key=lambda item: (item.file_path, item.start_line, item.vuln_type.lower()))
    return deduped


def _fallback_query_kb(chunk: CodeChunk, top_k: int, kb_docs: list[tuple[str, str, list[str], str]]) -> list[RetrievalHit]:
    tokens = {token.lower() for token in chunk.text.split() if len(token) >= 4}
    scored: list[tuple[float, tuple[str, str, list[str], str]]] = []
    for doc in kb_docs:
        doc_tokens = {token.lower() for token in doc[1].split() if len(token) >= 4}
        if not doc_tokens:
            continue
        overlap = tokens.intersection(doc_tokens)
        score = len(overlap) / len(doc_tokens)
        scored.append((min(max(score, 0.0), 1.0), doc))
    scored.sort(key=lambda item: item[0], reverse=True)
    hits: list[RetrievalHit] = []
    for score, (doc_id, content, tags, severity_guidance) in scored[: max(1, top_k)]:
        hits.append(
            RetrievalHit(
                id=doc_id,
                title=doc_id,
                score=score,
                severity_guidance=severity_guidance,
                tags=tags,
                preview=content[:240],
            )
        )
    return hits


def _emit_progress(progress_callback: Callable[[str], None] | None, message: str) -> None:
    if progress_callback is None:
        return
    progress_callback(message)


def scan_repo(
    path: str | Path,
    top_k: int | None = None,
    threshold: float | None = None,
    max_chunks: int | None = None,
    repair_retries: int | None = None,
    llm_timeout_seconds: float | None = None,
    model: str | None = None,
    chunk_size_lines: int | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> ScanReport:
    scan_started_at = datetime.now(timezone.utc)
    repo_path = Path(path).expanduser().resolve()
    if not repo_path.exists():
        raise FileNotFoundError(f"path does not exist: {repo_path}")
    if not repo_path.is_dir():
        raise NotADirectoryError(f"path is not a directory: {repo_path}")

    effective_top_k = max(1, top_k if top_k is not None else settings.scan_top_k)
    effective_threshold = min(max(threshold if threshold is not None else settings.scan_similarity_threshold, 0.0), 1.0)
    configured_max_chunks = max_chunks if max_chunks is not None else settings.scan_max_chunks
    effective_max_chunks = configured_max_chunks if configured_max_chunks > 0 else None
    effective_repair_retries = max(0, repair_retries if repair_retries is not None else settings.scan_repair_retries)
    effective_llm_timeout_seconds = (
        llm_timeout_seconds if llm_timeout_seconds is not None else settings.scan_llm_timeout_seconds
    )
    effective_model = model if model is not None else settings.scan_model
    effective_chunk_size_lines = max(1, chunk_size_lines if chunk_size_lines is not None else settings.chunk_size_lines)

    stats = ScanStats()
    errors: list[ScanChunkError] = []
    findings: list[Finding] = []

    raw_files = collect_files(root=repo_path)
    source_files = [SourceFile(**item) for item in raw_files]
    chunks = chunk_sources(source_files, chunk_size_lines=effective_chunk_size_lines)
    if effective_max_chunks is not None:
        chunks = chunks[:effective_max_chunks]

    stats.files_scanned = len(source_files)
    stats.chunks_considered = len(chunks)
    _emit_progress(
        progress_callback,
        (
            f"[scan] start repo={repo_path} files={stats.files_scanned} chunks={stats.chunks_considered} "
            f"top_k={effective_top_k} threshold={effective_threshold} timeout_s={effective_llm_timeout_seconds}"
        ),
    )

    kb_dir = _resolve_from_project(settings.kb_dir)
    persist_dir = _resolve_from_project(settings.chroma_persist_dir)
    persist_dir.mkdir(parents=True, exist_ok=True)

    kb_docs_payload: list[tuple[str, str, list[str], str]] = []
    store: ChromaStore | None = None
    try:
        kb_docs = load_kb_documents(kb_dir)
        kb_docs_payload = [
            (
                doc.id,
                doc.content,
                doc.tags,
                doc.severity_guidance,
            )
            for doc in kb_docs
        ]
        embedder = TextEmbedder(model=settings.embedding_model, batch_size=settings.embedding_batch_size)
        store = ChromaStore(
            persist_dir=str(persist_dir),
            collections=ChromaCollections(
                code_chunks=settings.chroma_collection_code_chunks,
                security_kb=settings.chroma_collection_security_kb,
            ),
            embedder=embedder,
        )
        store.upsert_kb_documents(kb_docs)
    except Exception as exc:
        logger.warning("Falling back to naive KB retrieval because KB index is unavailable: %s", exc)
        store = None

    llm_unavailable = False
    total_chunks = len(chunks)
    for chunk_index, chunk in enumerate(chunks, start=1):
        _emit_progress(
            progress_callback,
            f"[scan] chunk {chunk_index}/{total_chunks} {chunk.file_path}:{chunk.start_line}-{chunk.end_line}",
        )
        try:
            if store is not None:
                kb_hits = store.query_security_kb(query_text=chunk.text, top_k=effective_top_k, min_score=0.0)
            else:
                kb_hits = _fallback_query_kb(chunk=chunk, top_k=effective_top_k, kb_docs=kb_docs_payload)

            top_score = kb_hits[0].score if kb_hits else 0.0
            if top_score < effective_threshold:
                stats.skipped_low_similarity += 1
                _emit_progress(
                    progress_callback,
                    f"[scan] chunk {chunk_index}/{total_chunks} skipped_low_similarity score={top_score:.3f}",
                )
                continue

            if llm_unavailable:
                stats.chunks_skipped_exception += 1
                if len(errors) < MAX_REPORTED_ERRORS:
                    errors.append(
                        ScanChunkError(
                            file_path=chunk.file_path,
                            start_line=chunk.start_line,
                            end_line=chunk.end_line,
                            reason="llm_unavailable",
                        )
                    )
                _emit_progress(
                    progress_callback,
                    f"[scan] chunk {chunk_index}/{total_chunks} skipped llm_unavailable",
                )
                continue

            audit_result = audit_chunk_with_llm(
                chunk=chunk,
                kb_hits=kb_hits,
                model=effective_model,
                repair_retries=effective_repair_retries,
                timeout_seconds=effective_llm_timeout_seconds,
            )
            stats.llm_calls += audit_result.llm_calls
            stats.llm_retries += audit_result.llm_retries
            stats.llm_parse_failures += audit_result.parse_failures

            if audit_result.error_reason == "llm_unavailable":
                llm_unavailable = True
                stats.chunks_skipped_exception += 1
                if len(errors) < MAX_REPORTED_ERRORS:
                    errors.append(
                        ScanChunkError(
                            file_path=chunk.file_path,
                            start_line=chunk.start_line,
                            end_line=chunk.end_line,
                            reason="llm_unavailable",
                        )
                    )
                _emit_progress(
                    progress_callback,
                    f"[scan] chunk {chunk_index}/{total_chunks} skipped llm_unavailable",
                )
                continue

            if audit_result.skipped_parse_error:
                stats.chunks_skipped_parse_error += 1
                if len(errors) < MAX_REPORTED_ERRORS:
                    errors.append(
                        ScanChunkError(
                            file_path=chunk.file_path,
                            start_line=chunk.start_line,
                            end_line=chunk.end_line,
                            reason=f"llm_parse_error: {audit_result.error_reason}",
                        )
                    )
                _emit_progress(
                    progress_callback,
                    (
                        f"[scan] chunk {chunk_index}/{total_chunks} skipped_parse_error "
                        f"reason={audit_result.error_reason}"
                    ),
                )
                continue

            findings.extend([_normalize_finding(finding, repo_root=repo_path) for finding in audit_result.findings])
            _emit_progress(
                progress_callback,
                f"[scan] chunk {chunk_index}/{total_chunks} findings={len(audit_result.findings)}",
            )
        except Exception as exc:
            stats.chunks_skipped_exception += 1
            if len(errors) < MAX_REPORTED_ERRORS:
                errors.append(
                    ScanChunkError(
                        file_path=chunk.file_path,
                        start_line=chunk.start_line,
                        end_line=chunk.end_line,
                        reason=f"chunk_exception: {exc}",
                    )
                )
            _emit_progress(
                progress_callback,
                f"[scan] chunk {chunk_index}/{total_chunks} exception={exc}",
            )
            continue

    stats.findings_before_dedup = len(findings)
    deduped_findings = _dedupe_findings(findings)
    stats.findings_after_dedup = len(deduped_findings)

    scan_finished_at = datetime.now(timezone.utc)
    metadata = ScanMetadata(
        repo_path=str(repo_path),
        scan_started_at=scan_started_at,
        scan_finished_at=scan_finished_at,
        model=effective_model,
        top_k=effective_top_k,
        similarity_threshold=effective_threshold,
        max_chunks=effective_max_chunks,
        chunk_size_lines=effective_chunk_size_lines,
        repair_retries=effective_repair_retries,
    )
    _emit_progress(
        progress_callback,
        (
            f"[scan] done findings={stats.findings_after_dedup} llm_calls={stats.llm_calls} "
            f"parse_failures={stats.llm_parse_failures} skipped={stats.skipped_low_similarity + stats.chunks_skipped_parse_error + stats.chunks_skipped_exception}"
        ),
    )
    return ScanReport(metadata=metadata, stats=stats, findings=deduped_findings, errors=errors)
