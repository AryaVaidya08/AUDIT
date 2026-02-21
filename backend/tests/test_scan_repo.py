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


def test_scan_repo_retries_then_skips_parse_error_and_dedups(monkeypatch: object, tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    monkeypatch.setattr(scan_repo_module, "collect_files", lambda root: [{"path": "src/a.py", "text": "x"}])
    monkeypatch.setattr(scan_repo_module, "chunk_sources", lambda sources, chunk_size_lines: _sample_chunks())
    monkeypatch.setattr(
        scan_repo_module,
        "load_kb_documents",
        lambda kb_dir: [KBDocument(id="cwe-89", title="SQLi", tags=["sqli"], severity_guidance="high", content="x")],
    )
    monkeypatch.setattr(scan_repo_module, "TextEmbedder", _FakeEmbedder)
    monkeypatch.setattr(scan_repo_module, "ChromaStore", _HighScoreStore)

    def _fake_audit(chunk: CodeChunk, kb_hits: list[RetrievalHit], model: str, repair_retries: int) -> ChunkAuditResult:
        if chunk.file_path == "src/a.py":
            return ChunkAuditResult(
                findings=[],
                llm_calls=2,
                llm_retries=1,
                parse_failures=2,
                skipped_parse_error=True,
                error_reason="invalid_json",
            )
        finding = Finding(
            vuln_type="sql_injection",
            severity="high",
            confidence=0.9,
            references=["cwe-89"],
            file_path=str(repo_dir / "src/b.py"),
            start_line=10,
            end_line=10,
            message="Possible SQL injection.",
            evidence="Dynamic SQL query",
            recommendation="Use prepared statements",
        )
        return ChunkAuditResult(findings=[finding, finding], llm_calls=1, llm_retries=0, parse_failures=0)

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _fake_audit)

    report = scan_repo_module.scan_repo(path=repo_dir, threshold=0.2, max_chunks=10, model="gpt-4.1-mini")

    assert report.stats.files_scanned == 1
    assert report.stats.chunks_considered == 2
    assert report.stats.llm_calls == 3
    assert report.stats.llm_retries == 1
    assert report.stats.llm_parse_failures == 2
    assert report.stats.chunks_skipped_parse_error == 1
    assert report.stats.findings_before_dedup == 2
    assert report.stats.findings_after_dedup == 1
    assert len(report.findings) == 1
    assert report.findings[0].file_path == "src/b.py"
    assert len(report.errors) == 1
    assert "llm_parse_error" in report.errors[0].reason


def test_scan_repo_skips_low_similarity_without_llm_call(monkeypatch: object, tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    monkeypatch.setattr(scan_repo_module, "collect_files", lambda root: [{"path": "src/a.py", "text": "x"}])
    monkeypatch.setattr(scan_repo_module, "chunk_sources", lambda sources, chunk_size_lines: _sample_chunks())
    monkeypatch.setattr(
        scan_repo_module,
        "load_kb_documents",
        lambda kb_dir: [KBDocument(id="doc", title="Doc", tags=["x"], severity_guidance="low", content="doc")],
    )
    monkeypatch.setattr(scan_repo_module, "TextEmbedder", _FakeEmbedder)
    monkeypatch.setattr(scan_repo_module, "ChromaStore", _LowScoreStore)

    def _should_not_run(**_: object) -> ChunkAuditResult:
        raise AssertionError("audit_chunk_with_llm should not run when similarity is below threshold")

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _should_not_run)

    report = scan_repo_module.scan_repo(path=repo_dir, threshold=0.5, max_chunks=10, model="gpt-4.1-mini")
    assert report.stats.chunks_considered == 2
    assert report.stats.skipped_low_similarity == 2
    assert report.stats.llm_calls == 0
    assert report.findings == []
