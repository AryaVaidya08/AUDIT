from __future__ import annotations

from pathlib import Path

from app.scan.llm_audit import ChunkAuditResult
from app.scan.schema import CodeChunk, Finding, KBDocument, RetrievalHit
from app.scan import scan_repo as scan_repo_module


class _FakeEmbedder:
    def __init__(self, *_: object, **__: object):
        pass


class _HighScoreStore:
    def __init__(self, *_: object, **__: object):
        pass

    def upsert_kb_documents(self, docs: list[KBDocument]) -> int:
        return len(docs)

    def query_security_kb(self, query_text: str, top_k: int = 5, min_score: float | None = None) -> list[RetrievalHit]:
        _ = (top_k, min_score)
        return [
            RetrievalHit(
                id="cwe-89",
                title="SQL Injection",
                score=0.95,
                severity_guidance="high",
                tags=["sqli"],
                preview=query_text[:120],
            )
        ]


class _LowScoreStore(_HighScoreStore):
    def query_security_kb(self, query_text: str, top_k: int = 5, min_score: float | None = None) -> list[RetrievalHit]:
        _ = (top_k, min_score)
        return [
            RetrievalHit(
                id="low-signal",
                title="Low signal",
                score=0.05,
                severity_guidance="low",
                tags=[],
                preview=query_text[:120],
            )
        ]


def _sample_chunks() -> list[CodeChunk]:
    return [
        CodeChunk(file_path="src/a.py", start_line=1, end_line=20, text="print('a')"),
        CodeChunk(file_path="src/b.py", start_line=1, end_line=20, text="query = f\"SELECT * FROM users {value}\""),
    ]


def _sample_finding(repo_dir: Path, file_path: str, start_line: int = 10) -> Finding:
    return Finding(
        vuln_type="sql_injection",
        severity="high",
        confidence=0.9,
        references=["cwe-89"],
        file_path=str(repo_dir / file_path),
        start_line=start_line,
        end_line=start_line,
        message="Possible SQL injection.",
        evidence="Dynamic SQL query",
        recommendation="Use prepared statements",
    )


def _patch_scan_dependencies(monkeypatch: object, store_class: type[object], repo_dir: Path) -> None:
    monkeypatch.setattr(scan_repo_module, "collect_files", lambda root: [{"path": "src/a.py", "text": "x"}])
    monkeypatch.setattr(scan_repo_module, "chunk_sources", lambda sources, chunk_size_lines: _sample_chunks())
    monkeypatch.setattr(
        scan_repo_module,
        "load_kb_documents",
        lambda kb_dir: [KBDocument(id="cwe-89", title="SQLi", tags=["sqli"], severity_guidance="high", content="x")],
    )
    monkeypatch.setattr(scan_repo_module, "TextEmbedder", _FakeEmbedder)
    monkeypatch.setattr(scan_repo_module, "ChromaStore", store_class)


def test_scan_repo_retries_then_skips_parse_error_and_dedups(monkeypatch: object, tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _patch_scan_dependencies(monkeypatch=monkeypatch, store_class=_HighScoreStore, repo_dir=repo_dir)

    def _fake_audit(
        chunk: CodeChunk,
        kb_hits: list[RetrievalHit],
        model: str,
        repair_retries: int,
        timeout_seconds: float | None = None,
    ) -> ChunkAuditResult:
        _ = (kb_hits, model, repair_retries, timeout_seconds)
        if chunk.file_path == "src/a.py":
            return ChunkAuditResult(
                findings=[],
                llm_calls=2,
                llm_retries=1,
                parse_failures=2,
                skipped_parse_error=True,
                error_reason="invalid_json",
            )
        finding = _sample_finding(repo_dir, "src/b.py", start_line=10)
        return ChunkAuditResult(findings=[finding, finding], llm_calls=1, llm_retries=0, parse_failures=0)

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _fake_audit)

    report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=10,
        model="gpt-4.1-mini",
        cache_enabled=False,
    )

    assert report.stats.files_scanned == 1
    assert report.stats.chunks_considered == 2
    assert report.stats.chunks_prefiltered == 2
    assert report.stats.chunks_sent_to_llm == 2
    assert report.stats.cache_hits == 0
    assert report.stats.cache_misses == 2
    assert report.stats.llm_calls == 3
    assert report.stats.llm_retries == 1
    assert report.stats.llm_parse_failures == 2
    assert report.stats.llm_prompt_tokens == 0
    assert report.stats.llm_completion_tokens == 0
    assert report.stats.llm_total_tokens == 0
    assert report.stats.llm_estimated_cost_usd == 0.0
    assert report.stats.chunks_skipped_parse_error == 1
    assert report.stats.findings_before_dedup == 2
    assert report.stats.findings_after_dedup == 1
    assert report.stats.duration_ms >= 0
    assert report.stats.resume_used is False
    assert len(report.findings) == 1
    assert report.findings[0].file_path == "src/b.py"
    assert report.findings[0].code_content != ""
    assert len(report.findings[0].kb_evidence) == 1
    assert len(report.errors) == 1
    assert "llm_parse_error" in report.errors[0].reason
    assert report.metadata.chunking_strategy == "fixed_lines_no_overlap"
    assert report.metadata.embedding_model != ""


def test_scan_repo_skips_low_similarity_without_llm_call(monkeypatch: object, tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _patch_scan_dependencies(monkeypatch=monkeypatch, store_class=_LowScoreStore, repo_dir=repo_dir)

    def _should_not_run(**_: object) -> ChunkAuditResult:
        raise AssertionError("audit_chunk_with_llm should not run when similarity is below threshold")

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _should_not_run)

    report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.5,
        max_chunks=10,
        model="gpt-4.1-mini",
        cache_enabled=False,
    )
    assert report.stats.chunks_considered == 2
    assert report.stats.skipped_low_similarity == 2
    assert report.stats.llm_calls == 0
    assert report.stats.chunks_prefiltered == 0
    assert report.stats.chunks_sent_to_llm == 0
    assert report.findings == []


def test_scan_repo_second_run_uses_cache_and_keeps_findings_deterministic(monkeypatch: object, tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _patch_scan_dependencies(monkeypatch=monkeypatch, store_class=_HighScoreStore, repo_dir=repo_dir)

    call_count = {"value": 0}

    def _fake_audit(
        chunk: CodeChunk,
        kb_hits: list[RetrievalHit],
        model: str,
        repair_retries: int,
        timeout_seconds: float | None = None,
    ) -> ChunkAuditResult:
        _ = (kb_hits, model, repair_retries, timeout_seconds)
        call_count["value"] += 1
        if chunk.file_path == "src/a.py":
            finding = _sample_finding(repo_dir, "src/a.py", start_line=3)
        else:
            finding = _sample_finding(repo_dir, "src/b.py", start_line=7)
        return ChunkAuditResult(findings=[finding], llm_calls=1, llm_retries=0, parse_failures=0)

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _fake_audit)

    cache_path = tmp_path / "scan_cache.sqlite3"
    first_report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=10,
        model="gpt-4.1-mini",
        cache_enabled=True,
        cache_path=cache_path,
    )
    first_call_count = call_count["value"]

    second_report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=10,
        model="gpt-4.1-mini",
        cache_enabled=True,
        cache_path=cache_path,
    )

    assert first_report.stats.cache_hits == 0
    assert first_report.stats.cache_misses == 2
    assert second_report.stats.cache_hits > 0
    assert second_report.stats.cache_misses < first_report.stats.cache_misses
    assert call_count["value"] == first_call_count
    assert [item.model_dump() for item in first_report.findings] == [item.model_dump() for item in second_report.findings]
    dedup_keys = {(item.file_path, item.start_line, item.vuln_type.lower()) for item in second_report.findings}
    assert len(dedup_keys) == len(second_report.findings)


def test_scan_repo_handles_llm_timeout_without_crashing(monkeypatch: object, tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _patch_scan_dependencies(monkeypatch=monkeypatch, store_class=_HighScoreStore, repo_dir=repo_dir)

    def _fake_audit(
        chunk: CodeChunk,
        kb_hits: list[RetrievalHit],
        model: str,
        repair_retries: int,
        timeout_seconds: float | None = None,
    ) -> ChunkAuditResult:
        _ = (kb_hits, model, repair_retries, timeout_seconds)
        if chunk.file_path == "src/a.py":
            return ChunkAuditResult(
                findings=[],
                llm_calls=1,
                llm_retries=0,
                parse_failures=1,
                skipped_parse_error=True,
                error_reason="request timed out",
            )
        return ChunkAuditResult(findings=[_sample_finding(repo_dir, "src/b.py", start_line=11)], llm_calls=1)

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _fake_audit)

    report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=10,
        model="gpt-4.1-mini",
        cache_enabled=False,
    )

    assert report.stats.chunks_skipped_parse_error == 1
    assert report.stats.llm_parse_failures == 1
    assert report.stats.findings_after_dedup == 1
    assert len(report.errors) >= 1
    assert report.model_dump()["metadata"]["repo_path"] == str(repo_dir)


def test_scan_repo_handles_connection_error_without_crashing(monkeypatch: object, tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _patch_scan_dependencies(monkeypatch=monkeypatch, store_class=_HighScoreStore, repo_dir=repo_dir)

    def _fake_audit(
        chunk: CodeChunk,
        kb_hits: list[RetrievalHit],
        model: str,
        repair_retries: int,
        timeout_seconds: float | None = None,
    ) -> ChunkAuditResult:
        _ = (kb_hits, model, repair_retries, timeout_seconds)
        if chunk.file_path == "src/a.py":
            raise RuntimeError("connection reset")
        return ChunkAuditResult(findings=[_sample_finding(repo_dir, "src/b.py", start_line=9)], llm_calls=1)

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _fake_audit)

    report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=10,
        model="gpt-4.1-mini",
        cache_enabled=False,
    )

    assert report.stats.chunks_skipped_exception >= 1
    assert report.stats.findings_after_dedup == 1
    assert len(report.findings) == 1
    assert any("chunk_exception" in item.reason for item in report.errors)


def test_scan_repo_adds_secret_heuristic_findings_when_llm_misses(monkeypatch: object, tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _patch_scan_dependencies(monkeypatch=monkeypatch, store_class=_HighScoreStore, repo_dir=repo_dir)
    monkeypatch.setattr(
        scan_repo_module,
        "chunk_sources",
        lambda sources, chunk_size_lines: [
            CodeChunk(
                file_path="src/keys.py",
                start_line=1,
                end_line=3,
                text='API_KEY = "demo_hardcoded_key_123456789"\nprint("x")\nprint("y")',
            )
        ],
    )

    def _fake_audit(
        chunk: CodeChunk,
        kb_hits: list[RetrievalHit],
        model: str,
        repair_retries: int,
        timeout_seconds: float | None = None,
    ) -> ChunkAuditResult:
        _ = (chunk, kb_hits, model, repair_retries, timeout_seconds)
        return ChunkAuditResult(findings=[], llm_calls=1, llm_retries=0, parse_failures=0)

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _fake_audit)

    report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=10,
        model="gpt-4.1-mini",
        cache_enabled=False,
    )

    secret_findings = [finding for finding in report.findings if finding.vuln_type.startswith("SECRET.")]
    assert len(secret_findings) >= 1
    assert secret_findings[0].file_path == "src/keys.py"
    assert secret_findings[0].start_line == 1
    assert secret_findings[0].end_line == 1
    assert "API_KEY" in secret_findings[0].code_content
    assert len(secret_findings[0].kb_evidence) == 1
