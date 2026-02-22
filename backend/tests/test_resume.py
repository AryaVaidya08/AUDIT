from __future__ import annotations

from pathlib import Path

from app.scan.llm_audit import ChunkAuditResult
from app.scan.resume import ResumeCheckpoint
from app.scan.schema import CodeChunk, Finding, KBDocument, RetrievalHit, ScanStats
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
        _ = (query_text, top_k, min_score)
        return [
            RetrievalHit(
                id="cwe-89",
                title="SQL Injection",
                score=0.9,
                severity_guidance="high",
                tags=["sqli"],
                preview="hit",
            )
        ]


def _patch_common(monkeypatch: object) -> None:
    monkeypatch.setattr(
        scan_repo_module,
        "collect_files",
        lambda root: [{"path": "src/a.py", "text": "query = f\"SELECT * FROM users {value}\""}],
    )
    monkeypatch.setattr(
        scan_repo_module,
        "chunk_sources",
        lambda sources, chunk_size_lines: [CodeChunk(file_path="src/a.py", start_line=1, end_line=20, text="x")],
    )
    monkeypatch.setattr(
        scan_repo_module,
        "load_kb_documents",
        lambda kb_dir: [KBDocument(id="cwe-89", title="SQLi", tags=["sqli"], severity_guidance="high", content="x")],
    )
    monkeypatch.setattr(scan_repo_module, "TextEmbedder", _FakeEmbedder)
    monkeypatch.setattr(scan_repo_module, "ChromaStore", _HighScoreStore)
    monkeypatch.setattr(scan_repo_module, "compute_scan_params_signature", lambda params: "params-signature")
    monkeypatch.setattr(scan_repo_module, "compute_candidate_index_hash", lambda indices: "candidate-hash")
    monkeypatch.setattr(scan_repo_module, "compute_run_signature", lambda repo_path, scan_params_signature, candidate_index_hash: "run-signature")
    monkeypatch.setattr(scan_repo_module, "save_checkpoint", lambda path, checkpoint: None)


def test_resume_mismatch_falls_back_to_fresh_scan(monkeypatch: object, tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _patch_common(monkeypatch=monkeypatch)

    mismatch_checkpoint = ResumeCheckpoint(
        run_signature="wrong-run-signature",
        repo_path=str(repo_dir),
        scan_params_signature="params-signature",
        candidate_index_hash="candidate-hash",
        next_candidate_offset=1,
        partial_stats=ScanStats().model_dump(),
    )
    monkeypatch.setattr(scan_repo_module, "load_checkpoint", lambda path: mismatch_checkpoint)
    monkeypatch.setattr(
        scan_repo_module,
        "audit_chunk_with_llm",
        lambda **kwargs: ChunkAuditResult(findings=[], llm_calls=1, llm_retries=0, parse_failures=0),
    )

    report = scan_repo_module.scan_repo(
        path=repo_dir,
        resume=True,
        cache_enabled=False,
        checkpoint_path=tmp_path / "scan_resume.json",
    )

    assert report.stats.resume_used is False
    assert report.stats.llm_calls == 1


def test_resume_matching_checkpoint_restores_progress(monkeypatch: object, tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _patch_common(monkeypatch=monkeypatch)

    restored_finding = Finding(
        vuln_type="sql_injection",
        severity="high",
        confidence=0.8,
        references=["cwe-89"],
        file_path="src/a.py",
        start_line=10,
        end_line=10,
        message="Possible SQL injection.",
        evidence="Dynamic SQL",
        recommendation="Use prepared statements",
    )
    checkpoint = ResumeCheckpoint(
        run_signature="run-signature",
        repo_path=str(repo_dir),
        scan_params_signature="params-signature",
        candidate_index_hash="candidate-hash",
        next_candidate_offset=1,
        partial_stats=ScanStats(
            files_scanned=1,
            chunks_considered=1,
            chunks_prefiltered=1,
            chunks_sent_to_llm=1,
            cache_hits=0,
            cache_misses=1,
            findings_before_dedup=1,
            findings_after_dedup=1,
            resume_used=True,
        ).model_dump(),
        extras={
            "partial_errors": [],
            "partial_findings": [{"position": 0, "findings": [restored_finding.model_dump()]}],
        },
    )
    monkeypatch.setattr(scan_repo_module, "load_checkpoint", lambda path: checkpoint)

    def _should_not_run(**kwargs: object) -> ChunkAuditResult:
        raise AssertionError("LLM should not run when resume offset already completed all candidates")

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _should_not_run)

    report = scan_repo_module.scan_repo(
        path=repo_dir,
        resume=True,
        cache_enabled=False,
        checkpoint_path=tmp_path / "scan_resume.json",
    )

    assert report.stats.resume_used is True
    assert report.stats.findings_after_dedup == 1
    assert len(report.findings) == 1
    assert report.findings[0].file_path == "src/a.py"
