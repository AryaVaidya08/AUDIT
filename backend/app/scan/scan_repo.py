from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import settings
from app.embed.embeddings import TextEmbedder
from app.ingest.repo_loader import collect_files
from app.parse.chunkers import chunk_sources
from app.scan.cache import CacheRecord, ScanCache, build_cache_key, compute_chunk_hash
from app.scan.kb_loader import load_kb_documents
from app.scan.llm_audit import ChunkAuditResult, audit_chunk_with_llm
from app.scan.prefilter import select_candidates
from app.scan.prompts import PROMPT_VERSION
from app.scan.resume import (
    ResumeCheckpoint,
    compute_candidate_index_hash,
    compute_run_signature,
    compute_scan_params_signature,
    load_checkpoint,
    save_checkpoint,
)
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


def _coerce_partial_errors(payload: Any) -> list[ScanChunkError]:
    if not isinstance(payload, list):
        return []
    errors: list[ScanChunkError] = []
    for item in payload:
        try:
            errors.append(ScanChunkError.model_validate(item))
        except Exception:
            continue
    return errors[:MAX_REPORTED_ERRORS]


def _coerce_partial_findings(payload: Any) -> dict[int, list[Finding]]:
    if not isinstance(payload, list):
        return {}
    parsed: dict[int, list[Finding]] = {}
    for item in payload:
        if not isinstance(item, dict):
            continue
        try:
            position = int(item.get("position", -1))
        except (TypeError, ValueError):
            continue
        if position < 0:
            continue
        raw_findings = item.get("findings")
        if not isinstance(raw_findings, list):
            continue
        findings: list[Finding] = []
        is_valid = True
        for raw_finding in raw_findings:
            try:
                findings.append(Finding.model_validate(raw_finding))
            except Exception:
                is_valid = False
                break
        if is_valid:
            parsed[position] = findings
    return parsed


def _snapshot_partial_findings(candidate_findings: dict[int, list[Finding]], upto_offset: int) -> list[dict[str, Any]]:
    payload: list[dict[str, Any]] = []
    for position in sorted(position for position in candidate_findings if position < upto_offset):
        findings = candidate_findings.get(position, [])
        payload.append(
            {
                "position": position,
                "findings": [finding.model_dump() for finding in findings],
            }
        )
    return payload


def scan_repo(
    path: str | Path,
    top_k: int | None = None,
    threshold: float | None = None,
    max_chunks: int | None = None,
    repair_retries: int | None = None,
    llm_timeout_seconds: float | None = None,
    model: str | None = None,
    chunk_size_lines: int | None = None,
    resume: bool | None = None,
    prefilter_min_score: float | None = None,
    prefilter_max_candidates: int | None = None,
    max_inflight_llm_calls: int | None = None,
    cache_enabled: bool | None = None,
    cache_path: str | Path | None = None,
    checkpoint_path: str | Path | None = None,
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

    effective_prefilter_enabled = settings.scan_prefilter_enabled
    effective_prefilter_min_score = min(
        max(prefilter_min_score if prefilter_min_score is not None else settings.scan_prefilter_min_score, 0.0),
        1.0,
    )
    effective_prefilter_max_candidates = max(
        1,
        prefilter_max_candidates
        if prefilter_max_candidates is not None
        else settings.scan_prefilter_max_candidates,
    )
    effective_cache_enabled = settings.scan_cache_enabled if cache_enabled is None else bool(cache_enabled)
    effective_cache_path = _resolve_from_project(cache_path if cache_path is not None else settings.scan_cache_path)
    effective_max_inflight_llm_calls = max(
        1,
        max_inflight_llm_calls
        if max_inflight_llm_calls is not None
        else settings.scan_max_inflight_llm_calls,
    )
    effective_resume = bool(resume) if resume is not None else False
    effective_checkpoint_path = _resolve_from_project(
        checkpoint_path if checkpoint_path is not None else settings.scan_checkpoint_path
    )
    effective_checkpoint_every = max(1, settings.scan_checkpoint_every)

    stats = ScanStats()
    errors: list[ScanChunkError] = []
    candidate_findings: dict[int, list[Finding]] = {}

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

    _emit_progress(progress_callback, "[scan] stage=kb_prefilter start")
    kb_hits_by_chunk: dict[int, list[RetrievalHit]] = {}
    kb_scores: list[float] = []
    for chunk_index, chunk in enumerate(chunks):
        try:
            if store is not None:
                kb_hits = store.query_security_kb(query_text=chunk.text, top_k=effective_top_k, min_score=0.0)
            else:
                kb_hits = _fallback_query_kb(chunk=chunk, top_k=effective_top_k, kb_docs=kb_docs_payload)
        except Exception as exc:
            kb_hits = []
            if len(errors) < MAX_REPORTED_ERRORS:
                errors.append(
                    ScanChunkError(
                        file_path=chunk.file_path,
                        start_line=chunk.start_line,
                        end_line=chunk.end_line,
                        reason=f"kb_query_exception: {exc}",
                    )
                )
        kb_hits_by_chunk[chunk_index] = kb_hits
        kb_scores.append(kb_hits[0].score if kb_hits else 0.0)

    base_candidate_indices = [index for index, score in enumerate(kb_scores) if score >= effective_threshold]
    stats.skipped_low_similarity = len(chunks) - len(base_candidate_indices)

    if effective_prefilter_enabled:
        filtered_relative_indices = select_candidates(
            chunks=[chunks[index] for index in base_candidate_indices],
            kb_scores=[kb_scores[index] for index in base_candidate_indices],
            max_candidates=effective_prefilter_max_candidates,
            min_score=effective_prefilter_min_score,
        )
        candidate_indices = [base_candidate_indices[index] for index in filtered_relative_indices]
    else:
        candidate_indices = base_candidate_indices

    stats.chunks_prefiltered = len(candidate_indices)
    stats.chunks_sent_to_llm = len(candidate_indices)
    _emit_progress(
        progress_callback,
        (
            f"[scan] prefilter kept {stats.chunks_prefiltered}/{stats.chunks_considered} "
            f"(threshold_kept={len(base_candidate_indices)})"
        ),
    )

    scan_params_signature = compute_scan_params_signature(
        {
            "top_k": effective_top_k,
            "threshold": effective_threshold,
            "max_chunks": effective_max_chunks,
            "repair_retries": effective_repair_retries,
            "llm_timeout_seconds": effective_llm_timeout_seconds,
            "model": effective_model,
            "chunk_size_lines": effective_chunk_size_lines,
            "prefilter_enabled": effective_prefilter_enabled,
            "prefilter_min_score": effective_prefilter_min_score,
            "prefilter_max_candidates": effective_prefilter_max_candidates,
            "cache_enabled": effective_cache_enabled,
            "cache_path": str(effective_cache_path),
            "max_inflight_llm_calls": effective_max_inflight_llm_calls,
            "checkpoint_path": str(effective_checkpoint_path),
            "checkpoint_every": effective_checkpoint_every,
            "prompt_version": PROMPT_VERSION,
        }
    )
    candidate_index_hash = compute_candidate_index_hash(candidate_indices)
    run_signature = compute_run_signature(
        repo_path=str(repo_path),
        scan_params_signature=scan_params_signature,
        candidate_index_hash=candidate_index_hash,
    )

    resume_offset = 0
    if effective_resume:
        checkpoint = load_checkpoint(effective_checkpoint_path)
        if (
            checkpoint is not None
            and checkpoint.run_signature == run_signature
            and checkpoint.repo_path == str(repo_path)
            and checkpoint.scan_params_signature == scan_params_signature
            and checkpoint.candidate_index_hash == candidate_index_hash
        ):
            restored_stats: ScanStats | None = None
            try:
                restored_stats = ScanStats.model_validate(checkpoint.partial_stats)
            except Exception:
                restored_stats = None
            if restored_stats is not None:
                stats = restored_stats
            resume_offset = min(max(0, checkpoint.next_candidate_offset), len(candidate_indices))
            stats.resume_used = resume_offset > 0
            errors = _coerce_partial_errors(checkpoint.extras.get("partial_errors"))
            candidate_findings.update(_coerce_partial_findings(checkpoint.extras.get("partial_findings")))
            _emit_progress(
                progress_callback,
                f"[scan] resume accepted offset={resume_offset}/{len(candidate_indices)}",
            )
        else:
            _emit_progress(progress_callback, "[scan] resume ignored (missing or signature mismatch)")
    else:
        stats.resume_used = False

    cache: ScanCache | None = None
    cached_findings_by_key: dict[str, list[Finding]] = {}
    if effective_cache_enabled:
        try:
            cache = ScanCache(effective_cache_path)
            cache.ensure_schema()
        except Exception as exc:
            cache = None
            effective_cache_enabled = False
            _emit_progress(progress_callback, f"[scan] cache disabled due to schema error: {exc}")

    candidate_lookup: dict[int, tuple[str, str]] = {}
    for position, chunk_index in enumerate(candidate_indices):
        chunk = chunks[chunk_index]
        chunk_hash = compute_chunk_hash(chunk.text)
        cache_key = build_cache_key(
            repo_path=str(repo_path),
            file_path=chunk.file_path,
            start_line=chunk.start_line,
            end_line=chunk.end_line,
            chunk_hash=chunk_hash,
            model=effective_model,
            prompt_version=PROMPT_VERSION,
        )
        candidate_lookup[position] = (cache_key, chunk_hash)

    if cache is not None:
        cached_findings_by_key = cache.get_many([cache_key for cache_key, _ in candidate_lookup.values()])

    for position, (cache_key, _) in candidate_lookup.items():
        cached_findings = cached_findings_by_key.get(cache_key)
        if cached_findings is None:
            continue
        normalized = [_normalize_finding(finding, repo_root=repo_path) for finding in cached_findings]
        candidate_findings.setdefault(position, normalized)

    total_candidates = len(candidate_indices)
    active_positions = list(range(resume_offset, total_candidates))
    if effective_cache_enabled:
        active_cache_hit_positions = [position for position in active_positions if position in candidate_findings]
        active_miss_positions = [position for position in active_positions if position not in candidate_findings]
    else:
        active_cache_hit_positions = []
        active_miss_positions = active_positions[:]

    stats.cache_hits += len(active_cache_hit_positions)
    stats.cache_misses += len(active_miss_positions)
    _emit_progress(
        progress_callback,
        f"[scan] cache hits {len(active_cache_hit_positions)}, misses {len(active_miss_positions)}",
    )

    ready_results: dict[int, tuple[str, Any]] = {
        position: ("cache", candidate_findings.get(position, [])) for position in active_cache_hit_positions
    }
    next_apply_offset = resume_offset
    processed_since_checkpoint = 0

    def _write_checkpoint(next_candidate_offset: int) -> None:
        if not effective_resume:
            return
        checkpoint = ResumeCheckpoint(
            run_signature=run_signature,
            repo_path=str(repo_path),
            scan_params_signature=scan_params_signature,
            candidate_index_hash=candidate_index_hash,
            next_candidate_offset=next_candidate_offset,
            partial_stats=stats.model_dump(),
            extras={
                "partial_errors": [error.model_dump() for error in errors],
                "partial_findings": _snapshot_partial_findings(candidate_findings, upto_offset=next_candidate_offset),
            },
        )
        try:
            save_checkpoint(effective_checkpoint_path, checkpoint)
        except Exception as exc:
            _emit_progress(progress_callback, f"[scan] checkpoint write failed: {exc}")

    def _append_error(chunk: CodeChunk, reason: str) -> None:
        if len(errors) >= MAX_REPORTED_ERRORS:
            return
        errors.append(
            ScanChunkError(
                file_path=chunk.file_path,
                start_line=chunk.start_line,
                end_line=chunk.end_line,
                reason=reason,
            )
        )

    def _apply_ready_results() -> None:
        nonlocal next_apply_offset
        nonlocal processed_since_checkpoint

        while next_apply_offset < total_candidates and next_apply_offset in ready_results:
            kind, payload = ready_results.pop(next_apply_offset)
            chunk_index = candidate_indices[next_apply_offset]
            chunk = chunks[chunk_index]

            if kind == "cache":
                cached = payload if isinstance(payload, list) else []
                normalized_cached = [_normalize_finding(finding, repo_root=repo_path) for finding in cached]
                candidate_findings[next_apply_offset] = normalized_cached
                _emit_progress(
                    progress_callback,
                    (
                        f"[scan] candidate {next_apply_offset + 1}/{total_candidates} "
                        f"cache_hit findings={len(normalized_cached)}"
                    ),
                )
            elif kind == "llm":
                audit_result = payload
                if not isinstance(audit_result, ChunkAuditResult):
                    stats.chunks_skipped_exception += 1
                    candidate_findings[next_apply_offset] = []
                    _append_error(chunk, reason="chunk_exception: invalid_audit_result")
                    _emit_progress(
                        progress_callback,
                        f"[scan] candidate {next_apply_offset + 1}/{total_candidates} exception=invalid_audit_result",
                    )
                else:
                    stats.llm_calls += audit_result.llm_calls
                    stats.llm_retries += audit_result.llm_retries
                    stats.llm_parse_failures += audit_result.parse_failures

                    if audit_result.skipped_parse_error:
                        stats.chunks_skipped_parse_error += 1
                        candidate_findings[next_apply_offset] = []
                        _append_error(chunk, reason=f"llm_parse_error: {audit_result.error_reason}")
                        _emit_progress(
                            progress_callback,
                            (
                                f"[scan] candidate {next_apply_offset + 1}/{total_candidates} "
                                f"skipped_parse_error reason={audit_result.error_reason}"
                            ),
                        )
                    elif audit_result.error_reason == "llm_unavailable":
                        stats.chunks_skipped_exception += 1
                        candidate_findings[next_apply_offset] = []
                        _append_error(chunk, reason="llm_unavailable")
                        _emit_progress(
                            progress_callback,
                            f"[scan] candidate {next_apply_offset + 1}/{total_candidates} skipped llm_unavailable",
                        )
                    else:
                        normalized_fresh = [
                            _normalize_finding(finding=finding, repo_root=repo_path) for finding in audit_result.findings
                        ]
                        candidate_findings[next_apply_offset] = normalized_fresh
                        _emit_progress(
                            progress_callback,
                            (
                                f"[scan] candidate {next_apply_offset + 1}/{total_candidates} "
                                f"findings={len(normalized_fresh)}"
                            ),
                        )
                        if cache is not None:
                            cache_key, chunk_hash = candidate_lookup[next_apply_offset]
                            try:
                                cache.put_many(
                                    [
                                        CacheRecord(
                                            cache_key=cache_key,
                                            repo_path=str(repo_path),
                                            file_path=chunk.file_path,
                                            start_line=chunk.start_line,
                                            end_line=chunk.end_line,
                                            chunk_hash=chunk_hash,
                                            model=effective_model,
                                            prompt_version=PROMPT_VERSION,
                                            findings=normalized_fresh,
                                        )
                                    ]
                                )
                            except Exception as exc:
                                _emit_progress(
                                    progress_callback,
                                    (
                                        f"[scan] candidate {next_apply_offset + 1}/{total_candidates} "
                                        f"cache_write_error={exc}"
                                    ),
                                )
            else:
                stats.chunks_skipped_exception += 1
                candidate_findings[next_apply_offset] = []
                _append_error(chunk, reason=f"chunk_exception: {payload}")
                _emit_progress(
                    progress_callback,
                    (
                        f"[scan] candidate {next_apply_offset + 1}/{total_candidates} "
                        f"exception={payload}"
                    ),
                )

            next_apply_offset += 1
            processed_since_checkpoint += 1
            if effective_resume and processed_since_checkpoint >= effective_checkpoint_every:
                _write_checkpoint(next_candidate_offset=next_apply_offset)
                processed_since_checkpoint = 0

    if active_miss_positions:
        _emit_progress(
            progress_callback,
            (
                f"[scan] stage=llm start misses={len(active_miss_positions)} "
                f"max_inflight={effective_max_inflight_llm_calls}"
            ),
        )

        def _audit_position(position: int) -> ChunkAuditResult:
            chunk_index = candidate_indices[position]
            chunk = chunks[chunk_index]
            kb_hits = kb_hits_by_chunk.get(chunk_index, [])
            return audit_chunk_with_llm(
                chunk=chunk,
                kb_hits=kb_hits,
                model=effective_model,
                repair_retries=effective_repair_retries,
                timeout_seconds=effective_llm_timeout_seconds,
            )

        try:
            with ThreadPoolExecutor(max_workers=effective_max_inflight_llm_calls) as executor:
                futures = {executor.submit(_audit_position, position): position for position in active_miss_positions}
                _apply_ready_results()
                for future in as_completed(futures):
                    position = futures[future]
                    try:
                        ready_results[position] = ("llm", future.result())
                    except Exception as exc:
                        ready_results[position] = ("exception", exc)
                    _apply_ready_results()
        except KeyboardInterrupt:
            _emit_progress(progress_callback, "[scan] interrupted, writing checkpoint")
            _write_checkpoint(next_candidate_offset=next_apply_offset)
            raise

    _apply_ready_results()

    ordered_findings: list[Finding] = []
    for position in range(total_candidates):
        ordered_findings.extend(candidate_findings.get(position, []))

    stats.findings_before_dedup = len(ordered_findings)
    deduped_findings = _dedupe_findings(ordered_findings)
    stats.findings_after_dedup = len(deduped_findings)

    scan_finished_at = datetime.now(timezone.utc)
    stats.duration_ms = int((scan_finished_at - scan_started_at).total_seconds() * 1000)
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

    if effective_resume:
        completion_checkpoint = ResumeCheckpoint(
            run_signature=run_signature,
            repo_path=str(repo_path),
            scan_params_signature=scan_params_signature,
            candidate_index_hash=candidate_index_hash,
            next_candidate_offset=total_candidates,
            partial_stats=stats.model_dump(),
            extras={"completed": True},
        )
        try:
            save_checkpoint(effective_checkpoint_path, completion_checkpoint)
            effective_checkpoint_path.unlink(missing_ok=True)
        except Exception as exc:
            _emit_progress(progress_callback, f"[scan] checkpoint cleanup failed: {exc}")

    _emit_progress(
        progress_callback,
        (
            f"[scan] done findings={stats.findings_after_dedup} llm_calls={stats.llm_calls} "
            f"parse_failures={stats.llm_parse_failures} cache_hits={stats.cache_hits} "
            f"cache_misses={stats.cache_misses} duration_ms={stats.duration_ms}"
        ),
    )
    return ScanReport(metadata=metadata, stats=stats, findings=deduped_findings, errors=errors)
