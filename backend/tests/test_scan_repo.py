from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from app.scan.cache import CacheRecord, ScanCache, build_cache_key, compute_chunk_hash
from app.scan.candidate_stage import CandidateStageResult
from app.scan.llm_audit import ChunkAuditResult
from app.scan.schema import CodeChunk, Finding, KBDocument, RetrievalHit
from app.scan.taxonomy import restore_finding
from app.scan import scan_repo as scan_repo_module

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_REPO = REPO_ROOT / "demo_vuln_repo"


class _FakeEmbedder:
    def __init__(self, *_: object, **__: object):
        pass

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        return [[0.0] * 10 for _ in texts]


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

    def query_security_kb_batch(
        self, query_embeddings: list[list[float]], top_k: int = 5, min_score: float | None = None
    ) -> list[list[RetrievalHit]]:
        return [
            [
                RetrievalHit(
                    id="cwe-89",
                    title="SQL Injection",
                    score=0.95,
                    severity_guidance="high",
                    tags=["sqli"],
                    preview="batch",
                )
            ]
            for _ in query_embeddings
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

    def query_security_kb_batch(
        self, query_embeddings: list[list[float]], top_k: int = 5, min_score: float | None = None
    ) -> list[list[RetrievalHit]]:
        return [
            [
                RetrievalHit(
                    id="low-signal",
                    title="Low signal",
                    score=0.05,
                    severity_guidance="low",
                    tags=[],
                    preview="batch",
                )
            ]
            for _ in query_embeddings
        ]


class _MixedFallbackStore(_HighScoreStore):
    def query_security_kb(self, query_text: str, top_k: int = 5, min_score: float | None = None) -> list[RetrievalHit]:
        _ = (query_text, top_k, min_score)
        return [
            RetrievalHit(
                id="api-key-exposure",
                title="API Key and Token Exposure in Client-Side Code",
                score=0.39,
                severity_guidance="high",
                tags=["owasp-a02"],
                cwe="CWE-312",
                owasp_2021="A02:Cryptographic Failures",
                preview="api key",
            ),
            RetrievalHit(
                id="nosql-injection",
                title="NoSQL Injection (CWE-943)",
                score=0.38,
                severity_guidance="high",
                tags=["owasp-a03"],
                cwe="CWE-943",
                owasp_2021="A03:Injection",
                preview="nosql",
            ),
            RetrievalHit(
                id="graphql-abuse",
                title="GraphQL Introspection and Query Abuse",
                score=0.37,
                severity_guidance="medium",
                tags=["owasp-a05"],
                cwe="CWE-400",
                owasp_2021="A05:Security Misconfiguration",
                preview="graphql",
            ),
        ]

    def query_security_kb_batch(
        self, query_embeddings: list[list[float]], top_k: int = 5, min_score: float | None = None
    ) -> list[list[RetrievalHit]]:
        return [self.query_security_kb("batch", top_k=top_k, min_score=min_score) for _ in query_embeddings]


def _sample_chunks() -> list[CodeChunk]:
    return [
        CodeChunk(file_path="src/a.py", start_line=1, end_line=20, text="print('a')"),
        CodeChunk(file_path="src/b.py", start_line=1, end_line=20, text="query = f\"SELECT * FROM users {value}\""),
    ]


def _sample_finding(repo_dir: Path, file_path: str, start_line: int = 10) -> Finding:
    return Finding(
        vuln_type="sql_injection",
        title="SQL Injection",
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


def _patch_build_scan_chunks(
    monkeypatch: object,
    chunks: list[CodeChunk],
    *,
    candidate_strategy: str = "legacy_fixed_lines",
    supported_files: int = 0,
    regions_extracted: int = 0,
    files_fallback: int = 0,
) -> None:
    monkeypatch.setattr(
        scan_repo_module,
        "build_scan_chunks",
        lambda sources, chunk_size_lines, chunk_overlap_lines=0, candidate_stage_enabled=True: CandidateStageResult(
            scan_chunks=chunks,
            backstop_chunks=chunks,
            candidate_strategy=candidate_strategy if candidate_stage_enabled else "legacy_fixed_lines",
            supported_files=supported_files if candidate_stage_enabled else 0,
            regions_extracted=regions_extracted if candidate_stage_enabled else 0,
            files_fallback=files_fallback if candidate_stage_enabled else 0,
        ),
    )


def _patch_scan_dependencies(monkeypatch: object, store_class: type[object], repo_dir: Path) -> None:
    monkeypatch.setattr(scan_repo_module, "collect_files", lambda root: [{"path": "src/a.py", "text": "x"}])
    _patch_build_scan_chunks(monkeypatch=monkeypatch, chunks=_sample_chunks())
    monkeypatch.setattr(
        scan_repo_module,
        "load_kb_documents",
        lambda kb_dir: [KBDocument(id="cwe-89", title="SQLi", tags=["sqli"], severity_guidance="high", content="x")],
    )
    monkeypatch.setattr(scan_repo_module, "TextEmbedder", _FakeEmbedder)
    monkeypatch.setattr(scan_repo_module, "ChromaStore", store_class)
    monkeypatch.setattr(scan_repo_module, "validate_api_key", lambda: None)  # returns None = success


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
        "load_kb_documents",
        lambda kb_dir: [
            KBDocument(
                id="cwe-798-hardcoded-creds",
                title="Use of Hard-coded Credentials",
                tags=["cwe-798", "secrets"],
                severity_guidance="high",
                domain="crypto_secrets",
                cwe="CWE-798",
                content="Hard-coded credentials should be removed from source code.",
            )
        ],
    )
    monkeypatch.setattr(
        scan_repo_module,
        "build_scan_chunks",
        lambda sources, chunk_size_lines, chunk_overlap_lines=0, candidate_stage_enabled=True: CandidateStageResult(
            scan_chunks=[CodeChunk(file_path="src/safe.py", start_line=1, end_line=2, text='print("ok")\nprint("done")')],
            backstop_chunks=[
                CodeChunk(
                    file_path="src/keys.py",
                    start_line=1,
                    end_line=3,
                    text='API_KEY = "demo_hardcoded_key_123456789"\nprint("x")\nprint("y")',
                )
            ],
            candidate_strategy="structured_hybrid_v1" if candidate_stage_enabled else "legacy_fixed_lines",
            supported_files=1 if candidate_stage_enabled else 0,
            regions_extracted=1 if candidate_stage_enabled else 0,
            files_fallback=0,
        ),
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

    secret_findings = [finding for finding in report.findings if finding.vuln_type == "hardcoded_credentials"]
    assert len(secret_findings) >= 1
    assert secret_findings[0].file_path == "src/keys.py"
    assert secret_findings[0].start_line == 1
    assert secret_findings[0].end_line == 1
    assert "API_KEY" in secret_findings[0].code_content
    assert len(secret_findings[0].kb_evidence) == 1
    assert secret_findings[0].references == ["CWE-798"]


def test_scan_repo_adds_missing_admin_guard_heuristic_when_llm_misses(monkeypatch: object, tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _patch_scan_dependencies(monkeypatch=monkeypatch, store_class=_HighScoreStore, repo_dir=repo_dir)
    monkeypatch.setattr(
        scan_repo_module,
        "load_kb_documents",
        lambda kb_dir: [
            KBDocument(
                id="auth-missing-middleware",
                title="Missing Authentication or Authorization Middleware",
                tags=["auth", "access-control"],
                severity_guidance="high",
                domain="authn_session",
                cwe="CWE-306",
                owasp_2021="A01:Broken Access Control",
                content="Protected actions must enforce authentication and authorization checks.",
            )
        ],
    )
    monkeypatch.setattr(
        scan_repo_module,
        "build_scan_chunks",
        lambda sources, chunk_size_lines, chunk_overlap_lines=0, candidate_stage_enabled=True: CandidateStageResult(
            scan_chunks=[CodeChunk(file_path="src/safe.js", start_line=1, end_line=1, text="console.log('ok');")],
            backstop_chunks=[
                CodeChunk(
                    file_path="src/routes.js",
                    start_line=1,
                    end_line=5,
                    text=(
                        "const app = express();\n"
                        'app.get("/admin/users", (req, res) => {\n'
                        "  res.json({ ok: true });\n"
                        "});\n"
                        "module.exports = app;\n"
                    ),
                )
            ],
            candidate_strategy="structured_hybrid_v1" if candidate_stage_enabled else "legacy_fixed_lines",
            supported_files=1 if candidate_stage_enabled else 0,
            regions_extracted=1 if candidate_stage_enabled else 0,
            files_fallback=0,
        ),
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

    findings = [item for item in report.findings if item.vuln_type == "missing_auth_check"]
    assert len(findings) == 1
    assert findings[0].file_path == "src/routes.js"
    assert findings[0].start_line == 2
    assert findings[0].end_line == 2
    assert "admin/users" in findings[0].code_content
    assert len(findings[0].kb_evidence) == 1
    assert findings[0].kb_evidence[0].id == "auth-missing-middleware"
    assert findings[0].references == ["CWE-306", "OWASP-A01"]


def test_scan_repo_canonicalizes_eval_label_from_llm(monkeypatch: object, tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _patch_scan_dependencies(monkeypatch=monkeypatch, store_class=_HighScoreStore, repo_dir=repo_dir)
    monkeypatch.setattr(
        scan_repo_module,
        "load_kb_documents",
        lambda kb_dir: [
            KBDocument(
                id="unsafe-dynamic-code-execution",
                title="Unsafe Dynamic Code Execution (CWE-94)",
                tags=["cwe-94", "eval", "exec"],
                severity_guidance="critical",
                domain="injection",
                weakness_type="unsafe_dynamic_code_execution",
                cwe="CWE-94",
                owasp_2021="A03:Injection",
                content="Unsafe dynamic code execution can lead to remote code execution.",
            ),
            KBDocument(
                id="expression-language-injection",
                title="Expression Language Injection (CWE-917)",
                tags=["cwe-917", "rce"],
                severity_guidance="critical",
                domain="injection",
                weakness_type="expression_language_injection",
                cwe="CWE-917",
                owasp_2021="A03:Injection",
                content="Expression language injection can lead to remote code execution.",
            ),
        ],
    )
    monkeypatch.setattr(
        scan_repo_module,
        "build_scan_chunks",
        lambda sources, chunk_size_lines, chunk_overlap_lines=0, candidate_stage_enabled=True: CandidateStageResult(
            scan_chunks=[
                CodeChunk(
                    file_path="src/eval.py",
                    start_line=1,
                    end_line=2,
                    text="def run_expr(expr):\n    return eval(expr)\n",
                )
            ],
            backstop_chunks=[
                CodeChunk(
                    file_path="src/eval.py",
                    start_line=1,
                    end_line=2,
                    text="def run_expr(expr):\n    return eval(expr)\n",
                )
            ],
            candidate_strategy="structured_hybrid_v1" if candidate_stage_enabled else "legacy_fixed_lines",
            supported_files=1 if candidate_stage_enabled else 0,
            regions_extracted=1 if candidate_stage_enabled else 0,
            files_fallback=0,
        ),
    )

    def _fake_audit(
        chunk: CodeChunk,
        kb_hits: list[RetrievalHit],
        model: str,
        repair_retries: int,
        timeout_seconds: float | None = None,
    ) -> ChunkAuditResult:
        _ = (chunk, kb_hits, model, repair_retries, timeout_seconds)
        return ChunkAuditResult(
            findings=[
                Finding(
                    vuln_type="expression_language_injection",
                    title="Expression Language Injection",
                    severity="critical",
                    confidence=0.95,
                    references=["CWE-917"],
                    file_path="src/eval.py",
                    start_line=2,
                    end_line=2,
                    message="User input is evaluated with eval(), allowing arbitrary code execution.",
                    evidence="return eval(expr)",
                    recommendation="Avoid eval() on untrusted input.",
                )
            ],
            llm_calls=1,
            llm_retries=0,
            parse_failures=0,
        )

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _fake_audit)

    report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=10,
        model="gpt-4.1-mini",
        cache_enabled=False,
    )

    assert len(report.findings) == 1
    assert report.findings[0].vuln_type == "unsafe_dynamic_code_execution"
    assert report.findings[0].title == "Unsafe Dynamic Code Execution"
    assert report.findings[0].kb_evidence[0].id == "unsafe-dynamic-code-execution"
    assert report.findings[0].references == ["CWE-94", "OWASP-A03"]


def test_scan_repo_targets_kb_evidence_per_finding(monkeypatch: object, tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _patch_scan_dependencies(monkeypatch=monkeypatch, store_class=_HighScoreStore, repo_dir=repo_dir)
    monkeypatch.setattr(
        scan_repo_module,
        "load_kb_documents",
        lambda kb_dir: [
            KBDocument(
                id="cwe-89-sql-injection",
                title="SQL Injection (OWASP Injection, CWE-89)",
                tags=["cwe-89", "sqli"],
                severity_guidance="high",
                domain="injection",
                cwe="CWE-89",
                content="SQL injection occurs when untrusted input is concatenated into SQL queries.",
            ),
            KBDocument(
                id="unsafe-dynamic-code-execution",
                title="Unsafe Dynamic Code Execution (CWE-94)",
                tags=["cwe-94", "eval", "exec", "rce"],
                severity_guidance="critical",
                domain="injection",
                cwe="CWE-94",
                content="Unsafe dynamic code execution can lead to remote code execution.",
            ),
            KBDocument(
                id="expression-language-injection",
                title="Expression Language Injection (CWE-917)",
                tags=["cwe-917", "rce"],
                severity_guidance="critical",
                domain="injection",
                cwe="CWE-917",
                content="Expression language injection can lead to remote code execution.",
            ),
            KBDocument(
                id="unsafe-deserialization",
                title="Unsafe Native Deserialization (CWE-502)",
                tags=["cwe-502", "deserialization"],
                severity_guidance="critical",
                domain="deserialization_integrity",
                cwe="CWE-502",
                content="Unsafe deserialization can execute attacker-controlled payloads.",
            ),
        ],
    )
    monkeypatch.setattr(
        scan_repo_module,
        "build_scan_chunks",
        lambda sources, chunk_size_lines, chunk_overlap_lines=0, candidate_stage_enabled=True: CandidateStageResult(
            scan_chunks=[
                CodeChunk(
                    file_path="src/vuln.py",
                    start_line=1,
                    end_line=4,
                    text=(
                        'query = f"SELECT * FROM users WHERE id = {user_id}"\n'
                        "return eval(user_expression)\n"
                        "return pickle.loads(raw_blob)\n"
                        "print('done')\n"
                    ),
                )
            ],
            backstop_chunks=[
                CodeChunk(
                    file_path="src/vuln.py",
                    start_line=1,
                    end_line=4,
                    text=(
                        'query = f"SELECT * FROM users WHERE id = {user_id}"\n'
                        "return eval(user_expression)\n"
                        "return pickle.loads(raw_blob)\n"
                        "print('done')\n"
                    ),
                )
            ],
            candidate_strategy="structured_hybrid_v1" if candidate_stage_enabled else "legacy_fixed_lines",
            supported_files=1 if candidate_stage_enabled else 0,
            regions_extracted=1 if candidate_stage_enabled else 0,
            files_fallback=0,
        ),
    )

    def _fake_audit(
        chunk: CodeChunk,
        kb_hits: list[RetrievalHit],
        model: str,
        repair_retries: int,
        timeout_seconds: float | None = None,
    ) -> ChunkAuditResult:
        _ = (chunk, kb_hits, model, repair_retries, timeout_seconds)
        return ChunkAuditResult(
            findings=[
                Finding(
                    vuln_type="sql_injection",
                    title="SQL Injection",
                    severity="high",
                    confidence=0.9,
                    references=["CWE-89"],
                    file_path="src/vuln.py",
                    start_line=1,
                    end_line=1,
                    message="Dynamic SQL query concatenates untrusted input.",
                    evidence='query = f"SELECT * FROM users WHERE id = {user_id}"',
                    recommendation="Use parameterized queries.",
                ),
                Finding(
                    vuln_type="unsafe_dynamic_code_execution",
                    title="Unsafe Dynamic Code Execution",
                    severity="critical",
                    confidence=0.95,
                    references=["CWE-917"],
                    file_path="src/vuln.py",
                    start_line=2,
                    end_line=2,
                    message="User-controlled input reaches eval().",
                    evidence="return eval(user_expression)",
                    recommendation="Avoid eval() on untrusted data.",
                ),
                Finding(
                    vuln_type="unsafe_native_deserialization",
                    title="Unsafe Native Deserialization",
                    severity="critical",
                    confidence=0.9,
                    references=["CWE-502"],
                    file_path="src/vuln.py",
                    start_line=3,
                    end_line=3,
                    message="Untrusted bytes passed to pickle.loads.",
                    evidence="return pickle.loads(raw_blob)",
                    recommendation="Use safe formats like JSON.",
                ),
            ],
            llm_calls=1,
            llm_retries=0,
            parse_failures=0,
        )

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _fake_audit)

    report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=10,
        model="gpt-4.1-mini",
        cache_enabled=False,
    )

    finding_by_type = {finding.vuln_type: finding for finding in report.findings}
    assert finding_by_type["sql_injection"].kb_evidence[0].id == "cwe-89-sql-injection"
    assert finding_by_type["unsafe_dynamic_code_execution"].kb_evidence[0].id == "unsafe-dynamic-code-execution"
    assert finding_by_type["unsafe_native_deserialization"].kb_evidence[0].id == "unsafe-deserialization"


def test_scan_repo_backfills_demo_report_metadata_for_zero_confidence_findings(
    monkeypatch: object, tmp_path: Path
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _patch_scan_dependencies(monkeypatch=monkeypatch, store_class=_HighScoreStore, repo_dir=repo_dir)
    monkeypatch.setattr(
        scan_repo_module,
        "load_kb_documents",
        lambda kb_dir: [
            KBDocument(
                id="cwe-89-sql-injection",
                title="SQL Injection (OWASP Injection, CWE-89)",
                tags=["cwe-89", "sqli"],
                severity_guidance="high",
                domain="injection",
                cwe="CWE-89",
                owasp_2021="A03:Injection",
                content="SQL injection occurs when untrusted input is concatenated into SQL queries.",
            ),
            KBDocument(
                id="unsafe-dynamic-code-execution",
                title="Unsafe Dynamic Code Execution (CWE-94)",
                tags=["cwe-94", "eval", "exec", "rce"],
                severity_guidance="critical",
                domain="injection",
                cwe="CWE-94",
                owasp_2021="A03:Injection",
                content="Unsafe dynamic code execution can lead to remote code execution.",
            ),
            KBDocument(
                id="expression-language-injection",
                title="Expression Language Injection (CWE-917)",
                tags=["cwe-917", "rce"],
                severity_guidance="critical",
                domain="injection",
                cwe="CWE-917",
                owasp_2021="A03:Injection",
                content="Expression language injection can lead to remote code execution.",
            ),
            KBDocument(
                id="unsafe-deserialization",
                title="Unsafe Native Deserialization (CWE-502)",
                tags=["cwe-502", "deserialization"],
                severity_guidance="critical",
                domain="deserialization_integrity",
                cwe="CWE-502",
                owasp_2021="A08:Software and Data Integrity Failures",
                content="Unsafe deserialization can execute attacker-controlled payloads.",
            ),
        ],
    )
    monkeypatch.setattr(
        scan_repo_module,
        "build_scan_chunks",
        lambda sources, chunk_size_lines, chunk_overlap_lines=0, candidate_stage_enabled=True: CandidateStageResult(
            scan_chunks=[
                CodeChunk(
                    file_path="src/vuln.py",
                    start_line=1,
                    end_line=4,
                    text=(
                        'query = f"SELECT * FROM users WHERE id = {user_id}"\n'
                        "return eval(user_expression)\n"
                        "return pickle.loads(raw_blob)\n"
                        "print('done')\n"
                    ),
                )
            ],
            backstop_chunks=[
                CodeChunk(
                    file_path="src/vuln.py",
                    start_line=1,
                    end_line=4,
                    text=(
                        'query = f"SELECT * FROM users WHERE id = {user_id}"\n'
                        "return eval(user_expression)\n"
                        "return pickle.loads(raw_blob)\n"
                        "print('done')\n"
                    ),
                )
            ],
            candidate_strategy="structured_hybrid_v1" if candidate_stage_enabled else "legacy_fixed_lines",
            supported_files=1 if candidate_stage_enabled else 0,
            regions_extracted=1 if candidate_stage_enabled else 0,
            files_fallback=0,
        ),
    )

    def _fake_audit(
        chunk: CodeChunk,
        kb_hits: list[RetrievalHit],
        model: str,
        repair_retries: int,
        timeout_seconds: float | None = None,
    ) -> ChunkAuditResult:
        _ = (chunk, kb_hits, model, repair_retries, timeout_seconds)
        return ChunkAuditResult(
            findings=[
                Finding(
                    vuln_type="sql_injection",
                    title="SQL Injection",
                    severity="high",
                    confidence=0.0,
                    references=["cwe-89"],
                    file_path="src/vuln.py",
                    start_line=1,
                    end_line=1,
                    message="Dynamic SQL query concatenates untrusted input.",
                    evidence='query = f"SELECT * FROM users WHERE id = {user_id}"',
                    recommendation="Use parameterized queries.",
                ),
                Finding(
                    vuln_type="unsafe_dynamic_code_execution",
                    title="Unsafe Dynamic Code Execution",
                    severity="critical",
                    confidence=0.0,
                    references=[],
                    file_path="src/vuln.py",
                    start_line=2,
                    end_line=2,
                    message="User-controlled input reaches eval().",
                    evidence="return eval(user_expression)",
                    recommendation="Avoid eval() on untrusted data.",
                ),
                Finding(
                    vuln_type="unsafe_native_deserialization",
                    title="Unsafe Native Deserialization",
                    severity="critical",
                    confidence=0.0,
                    references=[],
                    file_path="src/vuln.py",
                    start_line=3,
                    end_line=3,
                    message="Untrusted bytes passed to pickle.loads.",
                    evidence="return pickle.loads(raw_blob)",
                    recommendation="Use safe formats like JSON.",
                ),
            ],
            llm_calls=1,
            llm_retries=0,
            parse_failures=0,
        )

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _fake_audit)

    report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=10,
        model="gpt-4.1-mini",
        cache_enabled=False,
    )

    finding_by_type = {finding.vuln_type: finding for finding in report.findings}

    sqli = finding_by_type["sql_injection"]
    assert sqli.confidence == 0.8
    assert sqli.kb_evidence[0].id == "cwe-89-sql-injection"
    assert sqli.references == ["CWE-89", "OWASP-A03"]

    eval_finding = finding_by_type["unsafe_dynamic_code_execution"]
    assert eval_finding.confidence == 0.8
    assert eval_finding.kb_evidence[0].id == "unsafe-dynamic-code-execution"
    assert eval_finding.references == ["CWE-94", "OWASP-A03"]

    deserialize_finding = finding_by_type["unsafe_native_deserialization"]
    assert deserialize_finding.confidence == 0.8
    assert deserialize_finding.kb_evidence[0].id == "unsafe-deserialization"
    assert deserialize_finding.references == ["CWE-502", "OWASP-A08"]


def test_scan_repo_prefers_deserialization_kb_evidence_over_broad_dynamic_label(
    monkeypatch: object, tmp_path: Path
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _patch_scan_dependencies(monkeypatch=monkeypatch, store_class=_HighScoreStore, repo_dir=repo_dir)
    monkeypatch.setattr(
        scan_repo_module,
        "load_kb_documents",
        lambda kb_dir: [
            KBDocument(
                id="unsafe-dynamic-code-execution",
                title="Unsafe Dynamic Code Execution (CWE-94)",
                tags=["cwe-94", "eval", "exec", "rce"],
                severity_guidance="critical",
                domain="injection",
                weakness_type="unsafe_dynamic_code_execution",
                cwe="CWE-94",
                owasp_2021="A03:Injection",
                content="Unsafe dynamic code execution can lead to remote code execution.",
            ),
            KBDocument(
                id="expression-language-injection",
                title="Expression Language Injection (CWE-917)",
                tags=["cwe-917", "rce"],
                severity_guidance="critical",
                domain="injection",
                weakness_type="expression_language_injection",
                cwe="CWE-917",
                owasp_2021="A03:Injection",
                content="Expression language injection can lead to remote code execution.",
            ),
            KBDocument(
                id="unsafe-deserialization",
                title="Unsafe Native Deserialization (CWE-502)",
                tags=["cwe-502", "deserialization"],
                severity_guidance="critical",
                domain="deserialization_integrity",
                weakness_type="unsafe_native_deserialization",
                cwe="CWE-502",
                owasp_2021="A08:Software and Data Integrity Failures",
                content="Unsafe deserialization can execute attacker-controlled payloads.",
            ),
        ],
    )
    monkeypatch.setattr(
        scan_repo_module,
        "build_scan_chunks",
        lambda sources, chunk_size_lines, chunk_overlap_lines=0, candidate_stage_enabled=True: CandidateStageResult(
            scan_chunks=[
                CodeChunk(
                    file_path="src/vuln.py",
                    start_line=1,
                    end_line=4,
                    text=(
                        "function runExpr(userInput) {\n"
                        "    return new Function(userInput)()\n"
                        "def load_blob(raw_blob):\n"
                        "    return pickle.loads(raw_blob)\n"
                    ),
                )
            ],
            backstop_chunks=[
                CodeChunk(
                    file_path="src/vuln.py",
                    start_line=1,
                    end_line=4,
                    text=(
                        "function runExpr(userInput) {\n"
                        "    return new Function(userInput)()\n"
                        "def load_blob(raw_blob):\n"
                        "    return pickle.loads(raw_blob)\n"
                    ),
                )
            ],
            candidate_strategy="structured_hybrid_v1" if candidate_stage_enabled else "legacy_fixed_lines",
            supported_files=1 if candidate_stage_enabled else 0,
            regions_extracted=1 if candidate_stage_enabled else 0,
            files_fallback=0,
        ),
    )

    def _fake_audit(
        chunk: CodeChunk,
        kb_hits: list[RetrievalHit],
        model: str,
        repair_retries: int,
        timeout_seconds: float | None = None,
    ) -> ChunkAuditResult:
        _ = (chunk, kb_hits, model, repair_retries, timeout_seconds)
        return ChunkAuditResult(
            findings=[
                Finding(
                    vuln_type="expression_language_injection",
                    title="Expression Language Injection",
                    severity="critical",
                    confidence=0.95,
                    references=["CWE-917"],
                    file_path="src/vuln.py",
                    start_line=2,
                    end_line=2,
                    message="User-controlled input reaches new Function().",
                    evidence="return new Function(userInput)()",
                    recommendation="Avoid new Function() on untrusted data.",
                ),
                Finding(
                    vuln_type="unsafe_dynamic_code_execution",
                    title="Unsafe Dynamic Code Execution",
                    severity="critical",
                    confidence=0.9,
                    references=["CWE-94"],
                    file_path="src/vuln.py",
                    start_line=4,
                    end_line=4,
                    message="Untrusted bytes passed to pickle.loads.",
                    evidence="return pickle.loads(raw_blob)",
                    recommendation="Use safe formats like JSON.",
                ),
            ],
            llm_calls=1,
            llm_retries=0,
            parse_failures=0,
        )

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _fake_audit)

    report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=10,
        model="gpt-4.1-mini",
        cache_enabled=False,
    )

    eval_findings = [finding for finding in report.findings if finding.vuln_type == "unsafe_dynamic_code_execution"]
    deserialize_findings = [
        finding for finding in report.findings if finding.vuln_type == "unsafe_native_deserialization"
    ]

    assert len(eval_findings) == 1
    assert len(deserialize_findings) == 1

    eval_finding = eval_findings[0]
    assert eval_finding.start_line == 2
    assert eval_finding.kb_evidence[0].id == "unsafe-dynamic-code-execution"
    assert eval_finding.references == ["CWE-94", "OWASP-A03"]

    deserialize_finding = deserialize_findings[0]
    assert deserialize_finding.start_line == 4
    assert deserialize_finding.kb_evidence[0].id == "unsafe-deserialization"
    assert deserialize_finding.references == ["CWE-502", "OWASP-A08"]


def test_scan_repo_accepts_kb_doc_ids_for_targeting_without_emitting_them(
    monkeypatch: object, tmp_path: Path
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _patch_scan_dependencies(monkeypatch=monkeypatch, store_class=_HighScoreStore, repo_dir=repo_dir)
    monkeypatch.setattr(
        scan_repo_module,
        "load_kb_documents",
        lambda kb_dir: [
            KBDocument(
                id="unsafe-dynamic-code-execution",
                title="Unsafe Dynamic Code Execution (CWE-94)",
                tags=["cwe-94", "eval", "exec", "rce"],
                severity_guidance="critical",
                domain="injection",
                cwe="CWE-94",
                owasp_2021="A03:Injection",
                content="Unsafe dynamic code execution can lead to remote code execution.",
            ),
            KBDocument(
                id="expression-language-injection",
                title="Expression Language Injection (CWE-917)",
                tags=["cwe-917", "rce"],
                severity_guidance="critical",
                domain="injection",
                cwe="CWE-917",
                owasp_2021="A03:Injection",
                content="Expression language injection can lead to remote code execution.",
            ),
            KBDocument(
                id="auth-missing-middleware",
                title="Missing Authentication or Authorization Middleware",
                tags=["auth", "access-control"],
                severity_guidance="high",
                domain="authn_session",
                cwe="CWE-306",
                owasp_2021="A01:Broken Access Control",
                content="Protected actions must enforce authentication and authorization checks.",
            ),
        ],
    )
    monkeypatch.setattr(
        scan_repo_module,
        "build_scan_chunks",
        lambda sources, chunk_size_lines, chunk_overlap_lines=0, candidate_stage_enabled=True: CandidateStageResult(
            scan_chunks=[
                CodeChunk(
                    file_path="src/vuln.py",
                    start_line=1,
                    end_line=3,
                    text="return eval(user_expression)\napp.get('/admin', handler)\nprint('done')\n",
                )
            ],
            backstop_chunks=[
                CodeChunk(
                    file_path="src/vuln.py",
                    start_line=1,
                    end_line=3,
                    text="return eval(user_expression)\napp.get('/admin', handler)\nprint('done')\n",
                )
            ],
            candidate_strategy="structured_hybrid_v1" if candidate_stage_enabled else "legacy_fixed_lines",
            supported_files=1 if candidate_stage_enabled else 0,
            regions_extracted=1 if candidate_stage_enabled else 0,
            files_fallback=0,
        ),
    )

    def _fake_audit(
        chunk: CodeChunk,
        kb_hits: list[RetrievalHit],
        model: str,
        repair_retries: int,
        timeout_seconds: float | None = None,
    ) -> ChunkAuditResult:
        _ = (chunk, kb_hits, model, repair_retries, timeout_seconds)
        return ChunkAuditResult(
            findings=[
                Finding(
                    vuln_type="unsafe_dynamic_code_execution",
                    title="Unsafe Dynamic Code Execution",
                    severity="critical",
                    confidence=0.95,
                    references=["expression-language-injection"],
                    file_path="src/vuln.py",
                    start_line=1,
                    end_line=1,
                    message="User-controlled input reaches eval().",
                    evidence="return eval(user_expression)",
                    recommendation="Avoid eval() on untrusted data.",
                ),
                Finding(
                    vuln_type="missing_auth_check",
                    title="Missing Authentication Check",
                    rule_id="AUTH.MISSING_ADMIN_GUARD",
                    severity="high",
                    confidence=0.85,
                    references=["auth-missing-middleware", "cwe-306"],
                    file_path="src/vuln.py",
                    start_line=2,
                    end_line=2,
                    message="Privileged route may be missing an auth check.",
                    evidence="app.get('/admin', handler)",
                    recommendation="Add authentication and authorization checks.",
                ),
            ],
            llm_calls=1,
            llm_retries=0,
            parse_failures=0,
        )

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _fake_audit)

    report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=10,
        model="gpt-4.1-mini",
        cache_enabled=False,
    )

    finding_by_line = {finding.start_line: finding for finding in report.findings}
    eval_finding = finding_by_line[1]
    auth_finding = finding_by_line[2]

    assert eval_finding.kb_evidence[0].id == "unsafe-dynamic-code-execution"
    assert eval_finding.references == ["CWE-94", "OWASP-A03"]
    assert "expression-language-injection" not in eval_finding.references

    assert auth_finding.kb_evidence[0].id == "auth-missing-middleware"
    assert auth_finding.references == ["CWE-306", "OWASP-A01"]
    assert "auth-missing-middleware" not in auth_finding.references


def test_scan_repo_does_not_attach_unrelated_fallback_kb_hits(monkeypatch: object, tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _patch_scan_dependencies(monkeypatch=monkeypatch, store_class=_MixedFallbackStore, repo_dir=repo_dir)
    monkeypatch.setattr(
        scan_repo_module,
        "load_kb_documents",
        lambda kb_dir: [
            KBDocument(
                id="api-key-exposure",
                title="API Key and Token Exposure in Client-Side Code",
                tags=["owasp-a02"],
                severity_guidance="high",
                domain="crypto_secrets",
                cwe="CWE-312",
                owasp_2021="A02:Cryptographic Failures",
                content="api key exposure",
            ),
            KBDocument(
                id="nosql-injection",
                title="NoSQL Injection (CWE-943)",
                tags=["owasp-a03"],
                severity_guidance="high",
                domain="injection",
                cwe="CWE-943",
                owasp_2021="A03:Injection",
                content="nosql injection",
            ),
            KBDocument(
                id="graphql-abuse",
                title="GraphQL Introspection and Query Abuse",
                tags=["owasp-a05"],
                severity_guidance="medium",
                domain="input_output_web",
                cwe="CWE-400",
                owasp_2021="A05:Security Misconfiguration",
                content="graphql abuse",
            ),
        ],
    )
    monkeypatch.setattr(
        scan_repo_module,
        "build_scan_chunks",
        lambda sources, chunk_size_lines, chunk_overlap_lines=0, candidate_stage_enabled=True: CandidateStageResult(
            scan_chunks=[
                CodeChunk(
                    file_path="src/routes.js",
                    start_line=1,
                    end_line=6,
                    text=(
                        "const app = express();\n"
                        "\n"
                        'app.get("/admin/users", (req, res) => {\n'
                        "  res.json({ ok: true });\n"
                        "});\n"
                        "module.exports = app;\n"
                    ),
                )
            ],
            backstop_chunks=[
                CodeChunk(
                    file_path="src/routes.js",
                    start_line=1,
                    end_line=6,
                    text=(
                        "const app = express();\n"
                        "\n"
                        'app.get("/admin/users", (req, res) => {\n'
                        "  res.json({ ok: true });\n"
                        "});\n"
                        "module.exports = app;\n"
                    ),
                )
            ],
            candidate_strategy="structured_hybrid_v1" if candidate_stage_enabled else "legacy_fixed_lines",
            supported_files=1 if candidate_stage_enabled else 0,
            regions_extracted=1 if candidate_stage_enabled else 0,
            files_fallback=0,
        ),
    )

    def _fake_audit(
        chunk: CodeChunk,
        kb_hits: list[RetrievalHit],
        model: str,
        repair_retries: int,
        timeout_seconds: float | None = None,
    ) -> ChunkAuditResult:
        _ = (chunk, kb_hits, model, repair_retries, timeout_seconds)
        return ChunkAuditResult(
            findings=[
                Finding(
                    vuln_type="missing_auth_check",
                    title="Missing Authentication Check",
                    severity="high",
                    confidence=0.0,
                    references=[],
                    file_path="src/routes.js",
                    start_line=3,
                    end_line=5,
                    message="Admin route is accessible without authentication.",
                    evidence='app.get("/admin/users", (req, res) => {',
                    recommendation="Add authentication and authorization checks.",
                )
            ],
            llm_calls=1,
            llm_retries=0,
            parse_failures=0,
        )

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _fake_audit)

    report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=10,
        model="gpt-4.1-mini",
        cache_enabled=False,
    )

    assert len(report.findings) == 1
    broad_finding = next(item for item in report.findings if item.vuln_type == "missing_auth_check")
    assert broad_finding.references == []
    assert broad_finding.kb_evidence == []


def test_scan_repo_cache_hit_recanonicalizes_old_reference_formats(monkeypatch: object, tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _patch_scan_dependencies(monkeypatch=monkeypatch, store_class=_HighScoreStore, repo_dir=repo_dir)
    monkeypatch.setattr(
        scan_repo_module,
        "load_kb_documents",
        lambda kb_dir: [
            KBDocument(
                id="cwe-89-sql-injection",
                title="SQL Injection (OWASP Injection, CWE-89)",
                tags=["cwe-89", "sqli"],
                severity_guidance="high",
                domain="injection",
                cwe="CWE-89",
                owasp_2021="A03:Injection",
                content="SQL injection occurs when untrusted input is concatenated into SQL queries.",
            )
        ],
    )
    monkeypatch.setattr(
        scan_repo_module,
        "build_scan_chunks",
        lambda sources, chunk_size_lines, chunk_overlap_lines=0, candidate_stage_enabled=True: CandidateStageResult(
            scan_chunks=[
                CodeChunk(
                    file_path="src/b.py",
                    start_line=1,
                    end_line=20,
                    text='query = f"SELECT * FROM users WHERE id = {user_id}"',
                )
            ],
            backstop_chunks=[
                CodeChunk(
                    file_path="src/b.py",
                    start_line=1,
                    end_line=20,
                    text='query = f"SELECT * FROM users WHERE id = {user_id}"',
                )
            ],
            candidate_strategy="structured_hybrid_v1" if candidate_stage_enabled else "legacy_fixed_lines",
            supported_files=1 if candidate_stage_enabled else 0,
            regions_extracted=1 if candidate_stage_enabled else 0,
            files_fallback=0,
        ),
    )

    def _should_not_run(**_: object) -> ChunkAuditResult:
        raise AssertionError("audit_chunk_with_llm should not run on a cache hit")

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _should_not_run)

    cache_path = tmp_path / "scan_cache.sqlite3"
    cache = ScanCache(cache_path)
    cache.ensure_schema()
    chunk_hash = compute_chunk_hash('query = f"SELECT * FROM users WHERE id = {user_id}"')
    cache_key = build_cache_key(
        repo_path=str(repo_dir),
        file_path="src/b.py",
        start_line=1,
        end_line=20,
        chunk_hash=chunk_hash,
        model="gpt-4.1-mini",
        prompt_version=scan_repo_module.PROMPT_VERSION,
    )
    cache.put_many(
        [
            CacheRecord(
                cache_key=cache_key,
                repo_path=str(repo_dir),
                file_path="src/b.py",
                start_line=1,
                end_line=20,
                chunk_hash=chunk_hash,
                model="gpt-4.1-mini",
                prompt_version=scan_repo_module.PROMPT_VERSION,
                findings=[
                    Finding(
                        vuln_type="sql_injection",
                        title="SQL Injection",
                        severity="high",
                        confidence=0.9,
                        references=["cwe-89-sql-injection"],
                        file_path="src/b.py",
                        start_line=1,
                        end_line=1,
                        message="Dynamic SQL query concatenates untrusted input.",
                        evidence='query = f"SELECT * FROM users WHERE id = {user_id}"',
                        recommendation="Use parameterized queries.",
                    )
                ],
            )
        ]
    )

    report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=10,
        model="gpt-4.1-mini",
        cache_enabled=True,
        cache_path=cache_path,
    )

    assert report.stats.cache_hits == 1
    assert len(report.findings) == 1
    assert report.findings[0].kb_evidence[0].id == "cwe-89-sql-injection"
    assert report.findings[0].references == ["CWE-89", "OWASP-A03"]


def test_scan_repo_cache_hit_drops_stale_fallback_references_without_explicit_match(
    monkeypatch: object, tmp_path: Path
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _patch_scan_dependencies(monkeypatch=monkeypatch, store_class=_MixedFallbackStore, repo_dir=repo_dir)
    monkeypatch.setattr(
        scan_repo_module,
        "load_kb_documents",
        lambda kb_dir: [
            KBDocument(
                id="api-key-exposure",
                title="API Key and Token Exposure in Client-Side Code",
                tags=["owasp-a02"],
                severity_guidance="high",
                domain="crypto_secrets",
                cwe="CWE-312",
                owasp_2021="A02:Cryptographic Failures",
                content="api key exposure",
            ),
            KBDocument(
                id="nosql-injection",
                title="NoSQL Injection (CWE-943)",
                tags=["owasp-a03"],
                severity_guidance="high",
                domain="injection",
                cwe="CWE-943",
                owasp_2021="A03:Injection",
                content="nosql injection",
            ),
            KBDocument(
                id="graphql-abuse",
                title="GraphQL Introspection and Query Abuse",
                tags=["owasp-a05"],
                severity_guidance="medium",
                domain="input_output_web",
                cwe="CWE-400",
                owasp_2021="A05:Security Misconfiguration",
                content="graphql abuse",
            ),
        ],
    )
    monkeypatch.setattr(
        scan_repo_module,
        "build_scan_chunks",
        lambda sources, chunk_size_lines, chunk_overlap_lines=0, candidate_stage_enabled=True: CandidateStageResult(
            scan_chunks=[
                CodeChunk(
                    file_path="src/routes.js",
                    start_line=1,
                    end_line=6,
                    text=(
                        "const app = express();\n"
                        "\n"
                        'app.get("/admin/users", (req, res) => {\n'
                        "  res.json({ ok: true });\n"
                        "});\n"
                        "module.exports = app;\n"
                    ),
                )
            ],
            backstop_chunks=[
                CodeChunk(
                    file_path="src/routes.js",
                    start_line=1,
                    end_line=6,
                    text=(
                        "const app = express();\n"
                        "\n"
                        'app.get("/admin/users", (req, res) => {\n'
                        "  res.json({ ok: true });\n"
                        "});\n"
                        "module.exports = app;\n"
                    ),
                )
            ],
            candidate_strategy="structured_hybrid_v1" if candidate_stage_enabled else "legacy_fixed_lines",
            supported_files=1 if candidate_stage_enabled else 0,
            regions_extracted=1 if candidate_stage_enabled else 0,
            files_fallback=0,
        ),
    )

    def _should_not_run(**_: object) -> ChunkAuditResult:
        raise AssertionError("audit_chunk_with_llm should not run on a cache hit")

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _should_not_run)
    stale_cached_finding = restore_finding(
        {
            "vuln_type": "Missing Authentication and Authorization",
            "severity": "high",
            "confidence": 0.0,
            "references": ["CWE-312", "CWE-400", "CWE-943", "OWASP-A02", "OWASP-A03", "OWASP-A05"],
            "file_path": "src/routes.js",
            "start_line": 3,
            "end_line": 5,
            "message": "Admin route is accessible without authentication.",
            "evidence": 'app.get("/admin/users", (req, res) => {',
            "kb_evidence": [
                {
                    "id": "api-key-exposure",
                    "title": "API Key and Token Exposure in Client-Side Code",
                    "score": 0.39,
                    "severity_guidance": "high",
                    "tags": ["owasp-a02"],
                    "cwe": "CWE-312",
                    "owasp_2021": "A02:Cryptographic Failures",
                    "preview": "api key",
                },
                {
                    "id": "nosql-injection",
                    "title": "NoSQL Injection (CWE-943)",
                    "score": 0.38,
                    "severity_guidance": "high",
                    "tags": ["owasp-a03"],
                    "cwe": "CWE-943",
                    "owasp_2021": "A03:Injection",
                    "preview": "nosql",
                },
            ],
            "recommendation": "Add authentication and authorization checks.",
        }
    )

    original_get_many = ScanCache.get_many

    def _fake_get_many(self: ScanCache, keys: list[str]) -> dict[str, list[Finding]]:
        cached = original_get_many(self, keys)
        if cached:
            return cached
        if not keys:
            return {}
        return {keys[0]: [stale_cached_finding]}

    monkeypatch.setattr(ScanCache, "get_many", _fake_get_many)

    cache_path = tmp_path / "scan_cache.sqlite3"

    report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=10,
        model="gpt-4.1-mini",
        cache_enabled=True,
        cache_path=cache_path,
    )

    assert report.stats.cache_hits == 1
    broad_finding = next(item for item in report.findings if item.vuln_type == "missing_auth_check")
    assert broad_finding.references == []
    assert broad_finding.kb_evidence == []


def test_scan_repo_continues_when_api_key_validation_has_connectivity_failure(monkeypatch: object, tmp_path: Path) -> None:
    """P1 regression: a transient connectivity failure during validate_api_key must not abort the scan."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    monkeypatch.setattr(scan_repo_module, "collect_files", lambda root: [{"path": "src/a.py", "text": "x"}])
    _patch_build_scan_chunks(monkeypatch=monkeypatch, chunks=_sample_chunks())
    monkeypatch.setattr(
        scan_repo_module,
        "load_kb_documents",
        lambda kb_dir: [KBDocument(id="cwe-89", title="SQLi", tags=["sqli"], severity_guidance="high", content="x")],
    )
    monkeypatch.setattr(scan_repo_module, "TextEmbedder", _FakeEmbedder)
    monkeypatch.setattr(scan_repo_module, "ChromaStore", _HighScoreStore)

    # simulate connectivity failure: validate_api_key returns a warning string
    monkeypatch.setattr(scan_repo_module, "validate_api_key", lambda: "Connection error (simulated)")

    def _fake_audit(
        chunk: CodeChunk,
        kb_hits: list[RetrievalHit],
        model: str,
        repair_retries: int,
        timeout_seconds: float | None = None,
    ) -> ChunkAuditResult:
        _ = (kb_hits, model, repair_retries, timeout_seconds)
        finding = _sample_finding(repo_dir, chunk.file_path, start_line=10)
        return ChunkAuditResult(findings=[finding], llm_calls=1, llm_retries=0, parse_failures=0)

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _fake_audit)

    progress_messages: list[str] = []
    report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=10,
        model="gpt-4.1-mini",
        cache_enabled=False,
        progress_callback=progress_messages.append,
    )

    # scan completed despite validation warning
    assert report.stats.findings_after_dedup >= 1
    assert any("warning" in msg for msg in progress_messages)


def test_scan_repo_raises_when_api_key_is_missing(monkeypatch: object, tmp_path: Path) -> None:
    """Missing key is a config error that must remain fatal."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    monkeypatch.setattr(scan_repo_module, "collect_files", lambda root: [{"path": "src/a.py", "text": "x"}])
    _patch_build_scan_chunks(monkeypatch=monkeypatch, chunks=_sample_chunks())
    monkeypatch.setattr(
        scan_repo_module,
        "load_kb_documents",
        lambda kb_dir: [KBDocument(id="cwe-89", title="SQLi", tags=["sqli"], severity_guidance="high", content="x")],
    )
    monkeypatch.setattr(scan_repo_module, "TextEmbedder", _FakeEmbedder)
    monkeypatch.setattr(scan_repo_module, "ChromaStore", _HighScoreStore)

    # validate_api_key raises RuntimeError for missing key — do NOT mock it away
    monkeypatch.setattr(scan_repo_module, "llm_is_available", lambda: True)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="OPENAI_API_KEY is not set"):
        scan_repo_module.scan_repo(
            path=repo_dir,
            threshold=0.2,
            max_chunks=10,
            model="gpt-4.1-mini",
            cache_enabled=False,
        )


def test_scan_repo_warns_on_chunk_truncation(monkeypatch: object, tmp_path: Path) -> None:
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
        return ChunkAuditResult(findings=[], llm_calls=1, llm_retries=0, parse_failures=0)

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _fake_audit)

    progress_messages: list[str] = []
    report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=1,
        model="gpt-4.1-mini",
        cache_enabled=False,
        progress_callback=progress_messages.append,
    )

    assert report.stats.chunks_truncated > 0
    assert report.stats.chunks_considered == 1
    assert any("truncat" in msg for msg in progress_messages)


def test_scan_repo_batch_kb_queries(monkeypatch: object, tmp_path: Path) -> None:
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
        _ = (model, repair_retries, timeout_seconds)
        finding = _sample_finding(repo_dir, chunk.file_path, start_line=10)
        return ChunkAuditResult(findings=[finding], llm_calls=1, llm_retries=0, parse_failures=0)

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _fake_audit)

    report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=10,
        model="gpt-4.1-mini",
        cache_enabled=False,
    )

    assert report.stats.chunks_considered == 2
    assert report.stats.findings_after_dedup >= 1
    assert len(report.findings[0].kb_evidence) >= 1


def test_scan_repo_candidate_stage_reduces_embedding_work(monkeypatch: object, tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    src_dir = repo_dir / "src"
    src_dir.mkdir()

    safe_helpers = "\n\n".join([f"def helper_{index}():\n    return {index}" for index in range(18)])
    (src_dir / "app.py").write_text(
        (
            f"{safe_helpers}\n\n"
            "def dangerous(user_id):\n"
            '    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
            "    return conn.execute(query)\n\n"
            f"{safe_helpers}\n"
        ),
        encoding="utf-8",
    )

    class _RecordingEmbedder(_FakeEmbedder):
        calls: list[int] = []

        def embed_texts(self, texts: list[str]) -> list[list[float]]:
            type(self).calls.append(len(texts))
            return super().embed_texts(texts)

    monkeypatch.setattr(
        scan_repo_module,
        "load_kb_documents",
        lambda kb_dir: [KBDocument(id="cwe-89", title="SQLi", tags=["sqli"], severity_guidance="high", content="x")],
    )
    monkeypatch.setattr(scan_repo_module, "TextEmbedder", _RecordingEmbedder)
    monkeypatch.setattr(scan_repo_module, "ChromaStore", _HighScoreStore)
    monkeypatch.setattr(scan_repo_module, "validate_api_key", lambda: None)
    monkeypatch.setattr(scan_repo_module, "llm_is_available", lambda: True)

    def _fake_audit(
        chunk: CodeChunk,
        kb_hits: list[RetrievalHit],
        model: str,
        repair_retries: int,
        timeout_seconds: float | None = None,
    ) -> ChunkAuditResult:
        _ = (kb_hits, model, repair_retries, timeout_seconds)
        findings: list[Finding] = []
        if "conn.execute(query)" in chunk.text:
            findings.append(_sample_finding(repo_dir, "src/app.py", start_line=39))
        return ChunkAuditResult(findings=findings, llm_calls=1, llm_retries=0, parse_failures=0)

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _fake_audit)

    _RecordingEmbedder.calls.clear()
    enabled_report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=100,
        model="gpt-4.1-mini",
        chunk_size_lines=20,
        cache_enabled=False,
        candidate_stage_enabled=True,
    )
    enabled_embed_count = _RecordingEmbedder.calls[-1]

    _RecordingEmbedder.calls.clear()
    disabled_report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=100,
        model="gpt-4.1-mini",
        chunk_size_lines=20,
        cache_enabled=False,
        candidate_stage_enabled=False,
    )
    disabled_embed_count = _RecordingEmbedder.calls[-1]

    enabled_vuln_types = {finding.vuln_type for finding in enabled_report.findings}
    disabled_vuln_types = {finding.vuln_type for finding in disabled_report.findings}

    assert enabled_embed_count < disabled_embed_count
    assert "sql_injection" in enabled_vuln_types
    assert "sql_injection" in disabled_vuln_types
    assert enabled_report.stats.findings_after_dedup == disabled_report.stats.findings_after_dedup
    assert enabled_report.metadata.candidate_strategy == "structured_hybrid_v1"
    assert disabled_report.metadata.candidate_strategy == "legacy_fixed_lines"
    assert disabled_report.stats.candidate_supported_files == 0


def test_scan_repo_candidate_stage_preserves_named_js_handler_findings_and_reduces_embedding_work(
    monkeypatch: object, tmp_path: Path
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    src_dir = repo_dir / "src"
    src_dir.mkdir()

    safe_helpers = "\n\n".join([f"function helper_{index}() {{\n  return {index};\n}}" for index in range(16)])
    source_text = (
        "const express = require(\"express\");\n"
        "const app = express();\n\n"
        'app.get("/admin/users", listUsers);\n\n'
        f"{safe_helpers}\n\n"
        "function helper() {\n"
        "  return true;\n"
        "}\n\n"
        f"{safe_helpers}\n\n"
        "function listUsers(req, res) {\n"
        "  const query = `SELECT * FROM users`;\n"
        "  return db.query(query);\n"
        "}\n\n"
        "module.exports = app;\n\n"
        f"{safe_helpers}\n"
    )
    (src_dir / "routes.js").write_text(source_text, encoding="utf-8")
    handler_line = source_text.splitlines().index("function listUsers(req, res) {") + 1

    class _RecordingEmbedder(_FakeEmbedder):
        calls: list[int] = []

        def embed_texts(self, texts: list[str]) -> list[list[float]]:
            type(self).calls.append(len(texts))
            return super().embed_texts(texts)

    monkeypatch.setattr(
        scan_repo_module,
        "load_kb_documents",
        lambda kb_dir: [KBDocument(id="cwe-89", title="SQLi", tags=["sqli"], severity_guidance="high", content="x")],
    )
    monkeypatch.setattr(scan_repo_module, "TextEmbedder", _RecordingEmbedder)
    monkeypatch.setattr(scan_repo_module, "ChromaStore", _HighScoreStore)
    monkeypatch.setattr(scan_repo_module, "validate_api_key", lambda: None)
    monkeypatch.setattr(scan_repo_module, "llm_is_available", lambda: True)

    def _fake_audit(
        chunk: CodeChunk,
        kb_hits: list[RetrievalHit],
        model: str,
        repair_retries: int,
        timeout_seconds: float | None = None,
    ) -> ChunkAuditResult:
        _ = (kb_hits, model, repair_retries, timeout_seconds)
        findings: list[Finding] = []
        if "return db.query(query);" in chunk.text:
            findings.append(_sample_finding(repo_dir, "src/routes.js", start_line=handler_line + 2))
        return ChunkAuditResult(findings=findings, llm_calls=1, llm_retries=0, parse_failures=0)

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _fake_audit)

    _RecordingEmbedder.calls.clear()
    enabled_report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=100,
        model="gpt-4.1-mini",
        chunk_size_lines=20,
        cache_enabled=False,
        candidate_stage_enabled=True,
    )
    enabled_embed_count = _RecordingEmbedder.calls[-1]

    _RecordingEmbedder.calls.clear()
    disabled_report = scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=100,
        model="gpt-4.1-mini",
        chunk_size_lines=20,
        cache_enabled=False,
        candidate_stage_enabled=False,
    )
    disabled_embed_count = _RecordingEmbedder.calls[-1]

    enabled_vuln_types = {finding.vuln_type for finding in enabled_report.findings}
    disabled_vuln_types = {finding.vuln_type for finding in disabled_report.findings}

    assert enabled_embed_count < disabled_embed_count
    assert "sql_injection" in enabled_vuln_types
    assert "sql_injection" in disabled_vuln_types
    assert enabled_report.stats.findings_after_dedup == disabled_report.stats.findings_after_dedup
    assert enabled_report.stats.candidate_supported_files == 1
    assert enabled_report.stats.candidate_regions_extracted == 2
    assert enabled_report.stats.candidate_files_fallback == 0
    assert enabled_report.metadata.candidate_strategy == "structured_hybrid_v1"
    assert disabled_report.metadata.candidate_strategy == "legacy_fixed_lines"


def test_scan_repo_candidate_stage_preserves_demo_repo_findings(monkeypatch: object) -> None:
    monkeypatch.setattr(
        scan_repo_module,
        "load_kb_documents",
        lambda kb_dir: [
            KBDocument(
                id="cwe-89-sql-injection",
                title="SQL Injection",
                tags=["cwe-89", "sqli"],
                severity_guidance="high",
                weakness_type="sql_injection",
                cwe="CWE-89",
                owasp_2021="A03:Injection",
                content="x",
            ),
            KBDocument(
                id="unsafe-dynamic-code-execution",
                title="Unsafe Dynamic Code Execution",
                tags=["cwe-94", "eval", "exec"],
                severity_guidance="critical",
                weakness_type="unsafe_dynamic_code_execution",
                cwe="CWE-94",
                owasp_2021="A03:Injection",
                content="x",
            ),
            KBDocument(
                id="expression-language-injection",
                title="Expression Language Injection",
                tags=["cwe-917"],
                severity_guidance="critical",
                weakness_type="expression_language_injection",
                cwe="CWE-917",
                owasp_2021="A03:Injection",
                content="x",
            ),
            KBDocument(
                id="unsafe-deserialization",
                title="Unsafe Native Deserialization",
                tags=["deserialization"],
                severity_guidance="critical",
                weakness_type="unsafe_native_deserialization",
                cwe="CWE-502",
                owasp_2021="A08:Software and Data Integrity Failures",
                content="x",
            ),
            KBDocument(
                id="auth-missing-middleware",
                title="Missing Authentication or Authorization Middleware",
                tags=["auth"],
                severity_guidance="high",
                weakness_type="missing_auth_check",
                cwe="CWE-306",
                owasp_2021="A01:Broken Access Control",
                content="x",
            ),
        ],
    )
    monkeypatch.setattr(scan_repo_module, "TextEmbedder", _FakeEmbedder)
    monkeypatch.setattr(scan_repo_module, "ChromaStore", _HighScoreStore)
    monkeypatch.setattr(scan_repo_module, "validate_api_key", lambda: None)
    monkeypatch.setattr(scan_repo_module, "llm_is_available", lambda: True)

    def _fake_audit(
        chunk: CodeChunk,
        kb_hits: list[RetrievalHit],
        model: str,
        repair_retries: int,
        timeout_seconds: float | None = None,
    ) -> ChunkAuditResult:
        _ = (kb_hits, model, repair_retries, timeout_seconds)
        findings: list[Finding] = []
        if "conn.execute(query)" in chunk.text:
            findings.append(
                Finding(
                    vuln_type="sql_injection",
                    title="SQL Injection",
                    severity="high",
                    confidence=0.9,
                    references=["CWE-89"],
                    file_path="vuln_app.py",
                    start_line=7,
                    end_line=7,
                    message="Dynamic SQL query concatenates untrusted input.",
                    evidence="return conn.execute(query).fetchall()",
                    recommendation="Use parameterized queries.",
                )
            )
        if "eval(user_expression)" in chunk.text:
            findings.append(
                Finding(
                    vuln_type="unsafe_dynamic_code_execution",
                    title="Unsafe Dynamic Code Execution",
                    rule_id="CODE_EXEC.DYNAMIC_EVAL",
                    severity="critical",
                    confidence=0.95,
                    references=["CWE-917"],
                    file_path="vuln_app.py",
                    start_line=10,
                    end_line=10,
                    message="User-controlled input reaches eval().",
                    evidence="return eval(user_expression)",
                    recommendation="Avoid eval() on untrusted data.",
                )
            )
        if "pickle.loads(raw_blob)" in chunk.text:
            findings.append(
                Finding(
                    vuln_type="unsafe_native_deserialization",
                    title="Unsafe Native Deserialization",
                    severity="critical",
                    confidence=0.9,
                    references=["CWE-502"],
                    file_path="vuln_app.py",
                    start_line=13,
                    end_line=13,
                    message="Untrusted bytes passed to pickle.loads.",
                    evidence="return pickle.loads(raw_blob)",
                    recommendation="Use safe formats like JSON.",
                )
            )
        return ChunkAuditResult(findings=findings, llm_calls=1, llm_retries=0, parse_failures=0)

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _fake_audit)

    report = scan_repo_module.scan_repo(
        path=DEMO_REPO,
        threshold=0.2,
        max_chunks=100,
        model="gpt-4.1-mini",
        chunk_size_lines=20,
        cache_enabled=False,
        candidate_stage_enabled=True,
    )

    vuln_types = {finding.vuln_type for finding in report.findings}
    assert "sql_injection" in vuln_types
    assert "unsafe_dynamic_code_execution" in vuln_types
    assert "unsafe_native_deserialization" in vuln_types
    assert "missing_auth_check" in vuln_types

    eval_findings = [
        finding
        for finding in report.findings
        if finding.file_path == "vuln_app.py"
        and finding.start_line == 10
        and finding.vuln_type == "unsafe_dynamic_code_execution"
    ]
    deserialize_findings = [
        finding
        for finding in report.findings
        if finding.file_path == "vuln_app.py"
        and finding.start_line == 13
        and finding.vuln_type == "unsafe_native_deserialization"
    ]

    assert len(eval_findings) == 1
    assert len(deserialize_findings) == 1


def test_scan_repo_backstop_recovers_demo_repo_findings_when_llm_path_fails(monkeypatch: object) -> None:
    monkeypatch.setattr(
        scan_repo_module,
        "load_kb_documents",
        lambda kb_dir: [
            KBDocument(
                id="cwe-798-hardcoded-creds",
                title="Hardcoded Credentials (CWE-798)",
                tags=["cwe-798"],
                severity_guidance="high",
                cwe="CWE-798",
                owasp_2021="A07:Identification and Authentication Failures",
                content="x",
            ),
            KBDocument(
                id="cwe-89-sql-injection",
                title="SQL Injection (OWASP Injection, CWE-89)",
                tags=["cwe-89"],
                severity_guidance="high",
                cwe="CWE-89",
                owasp_2021="A03:Injection",
                content="x",
            ),
            KBDocument(
                id="unsafe-dynamic-code-execution",
                title="Unsafe Dynamic Code Execution",
                tags=["cwe-94"],
                severity_guidance="high",
                cwe="CWE-94",
                owasp_2021="A03:Injection",
                content="x",
            ),
            KBDocument(
                id="expression-language-injection",
                title="Expression Language Injection",
                tags=["cwe-917"],
                severity_guidance="high",
                cwe="CWE-917",
                owasp_2021="A03:Injection",
                content="x",
            ),
            KBDocument(
                id="unsafe-deserialization",
                title="Unsafe Native Deserialization",
                tags=["cwe-502"],
                severity_guidance="critical",
                cwe="CWE-502",
                owasp_2021="A08:Software and Data Integrity Failures",
                content="x",
            ),
            KBDocument(
                id="auth-missing-middleware",
                title="Missing Authentication or Authorization Middleware",
                tags=["cwe-306"],
                severity_guidance="high",
                cwe="CWE-306",
                owasp_2021="A01:Broken Access Control",
                content="x",
            ),
        ],
    )
    monkeypatch.setattr(scan_repo_module, "TextEmbedder", _FakeEmbedder)
    monkeypatch.setattr(scan_repo_module, "ChromaStore", _HighScoreStore)
    monkeypatch.setattr(scan_repo_module, "validate_api_key", lambda: None)
    monkeypatch.setattr(scan_repo_module, "llm_is_available", lambda: True)

    def _failing_audit(
        chunk: CodeChunk,
        kb_hits: list[RetrievalHit],
        model: str,
        repair_retries: int,
        timeout_seconds: float | None = None,
    ) -> ChunkAuditResult:
        _ = (chunk, kb_hits, model, repair_retries, timeout_seconds)
        return ChunkAuditResult(
            findings=[],
            llm_calls=0,
            llm_retries=1,
            parse_failures=0,
            skipped_parse_error=True,
            error_reason="response_format rejected",
        )

    monkeypatch.setattr(scan_repo_module, "audit_chunk_with_llm", _failing_audit)

    report = scan_repo_module.scan_repo(
        path=DEMO_REPO,
        threshold=0.2,
        max_chunks=100,
        model="gpt-4.1-mini",
        chunk_size_lines=20,
        cache_enabled=False,
        candidate_stage_enabled=True,
    )

    vuln_types = {finding.vuln_type for finding in report.findings}
    assert "hardcoded_credentials" in vuln_types
    assert "sql_injection" in vuln_types
    assert "unsafe_dynamic_code_execution" in vuln_types
    assert "unsafe_native_deserialization" in vuln_types
    assert "missing_auth_check" in vuln_types
    assert report.stats.chunks_skipped_parse_error == report.stats.chunks_sent_to_llm


def test_scan_repo_resolves_relative_chroma_path_from_scanned_repo(monkeypatch: object, tmp_path: Path) -> None:
    repo_dir = tmp_path / "workspace" / "demo-repo"
    repo_dir.mkdir(parents=True)
    launch_dir = tmp_path / "launcher"
    launch_dir.mkdir()
    monkeypatch.chdir(launch_dir)
    _patch_scan_dependencies(monkeypatch=monkeypatch, store_class=_HighScoreStore, repo_dir=repo_dir)

    recorded: dict[str, str] = {}

    class _RecordingStore(_HighScoreStore):
        def __init__(self, persist_dir: str, *_: object, **__: object):
            recorded["persist_dir"] = persist_dir

    monkeypatch.setattr(scan_repo_module, "ChromaStore", _RecordingStore)
    monkeypatch.setattr(
        scan_repo_module,
        "settings",
        replace(
            scan_repo_module.settings,
            chroma_persist_dir=".chroma",
            scan_cache_path=".audit/scan_cache.sqlite3",
            scan_checkpoint_path=".audit/scan_resume.json",
        ),
    )
    monkeypatch.setattr(
        scan_repo_module,
        "audit_chunk_with_llm",
        lambda chunk, kb_hits, model, repair_retries, timeout_seconds=None: ChunkAuditResult(
            findings=[], llm_calls=1, llm_retries=0, parse_failures=0
        ),
    )

    scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=10,
        model="gpt-4.1-mini",
        cache_enabled=False,
    )

    assert recorded["persist_dir"] == str((repo_dir / ".chroma").resolve())
    assert not (launch_dir / ".chroma").exists()


def test_scan_repo_does_not_leave_empty_chroma_dir_when_store_init_fails(
    monkeypatch: object,
    tmp_path: Path,
) -> None:
    repo_dir = tmp_path / "workspace" / "demo-repo"
    repo_dir.mkdir(parents=True)
    launch_dir = tmp_path / "launcher"
    launch_dir.mkdir()
    monkeypatch.chdir(launch_dir)
    _patch_scan_dependencies(monkeypatch=monkeypatch, store_class=_HighScoreStore, repo_dir=repo_dir)

    class _FailingStore:
        def __init__(self, *_: object, **__: object):
            raise RuntimeError("vector store unavailable")

    monkeypatch.setattr(scan_repo_module, "ChromaStore", _FailingStore)
    monkeypatch.setattr(
        scan_repo_module,
        "settings",
        replace(
            scan_repo_module.settings,
            chroma_persist_dir=".chroma",
            scan_cache_path=".audit/scan_cache.sqlite3",
            scan_checkpoint_path=".audit/scan_resume.json",
        ),
    )
    monkeypatch.setattr(
        scan_repo_module,
        "audit_chunk_with_llm",
        lambda chunk, kb_hits, model, repair_retries, timeout_seconds=None: ChunkAuditResult(
            findings=[], llm_calls=1, llm_retries=0, parse_failures=0
        ),
    )

    scan_repo_module.scan_repo(
        path=repo_dir,
        threshold=0.2,
        max_chunks=10,
        model="gpt-4.1-mini",
        cache_enabled=False,
    )

    assert not (repo_dir / ".chroma").exists()
    assert not (launch_dir / ".chroma").exists()
