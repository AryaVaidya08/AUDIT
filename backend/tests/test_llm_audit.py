from __future__ import annotations

from app.scan.llm_audit import audit_chunk_with_llm
from app.scan.schema import CodeChunk, RetrievalHit


class _FakeResponseMessage:
    def __init__(self, content: str):
        self.content = content


class _FakeResponseChoice:
    def __init__(self, content: str):
        self.message = _FakeResponseMessage(content)


class _FakeResponse:
    def __init__(self, content: str):
        self.choices = [_FakeResponseChoice(content)]


class _FakeCompletions:
    def __init__(self, outputs: list[str]):
        self._outputs = outputs[:]

    def create(self, **_: object) -> _FakeResponse:
        next_output = self._outputs.pop(0) if self._outputs else "[]"
        return _FakeResponse(next_output)


class _FakeChat:
    def __init__(self, outputs: list[str]):
        self.completions = _FakeCompletions(outputs)


class _FakeClient:
    def __init__(self, outputs: list[str]):
        self.chat = _FakeChat(outputs)


def _sample_chunk() -> CodeChunk:
    return CodeChunk(file_path="src/app.py", start_line=5, end_line=25, text="query = f'SELECT * FROM users {value}'")


def _sample_hits() -> list[RetrievalHit]:
    return [
        RetrievalHit(
            id="cwe-89",
            title="SQL Injection",
            score=0.92,
            severity_guidance="high",
            tags=["sqli"],
            preview="Avoid dynamic SQL.",
        )
    ]


def test_audit_chunk_repairs_and_normalizes_output() -> None:
    client = _FakeClient(
        outputs=[
            "not-json-at-all",
            """
            [
              {
                "vuln_type": "SQLI",
                "severity": "Severe",
                "confidence": 1.7,
                "references": "cwe-89",
                "file_path": "/tmp/demo/src/app.py",
                "start_line": 12,
                "end_line": 10,
                "message": "Potential SQL injection\\nextra",
                "evidence": "dynamic query",
                "recommendation": "parameterize query"
              }
            ]
            """.strip(),
        ]
    )
    result = audit_chunk_with_llm(
        chunk=_sample_chunk(),
        kb_hits=_sample_hits(),
        model="gpt-4.1-mini",
        repair_retries=1,
        client=client,
    )

    assert result.skipped_parse_error is False
    assert result.llm_calls == 2
    assert result.llm_retries == 1
    assert result.parse_failures == 1
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == "critical"
    assert finding.confidence == 1.0
    assert finding.end_line == 12
    assert finding.message == "Potential SQL injection"
    assert finding.references == ["cwe-89"]


def test_audit_chunk_skips_after_retry_failure() -> None:
    client = _FakeClient(outputs=["not-json", "still not-json"])
    result = audit_chunk_with_llm(
        chunk=_sample_chunk(),
        kb_hits=_sample_hits(),
        model="gpt-4.1-mini",
        repair_retries=1,
        client=client,
    )

    assert result.findings == []
    assert result.skipped_parse_error is True
    assert result.llm_calls == 2
    assert result.llm_retries == 1
    assert result.parse_failures == 2
