from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.scan.schema import Finding, ScanMetadata, ScanReport, ScanStats


def _base_finding_payload() -> dict[str, object]:
    return {
        "vuln_type": "sql_injection",
        "severity": "high",
        "confidence": 0.8,
        "references": ["cwe-89"],
        "file_path": "src/demo.py",
        "start_line": 10,
        "end_line": 10,
        "message": "Possible SQL injection.",
        "evidence": "query = f\"SELECT ... {user_input}\"",
        "recommendation": "Use parameterized queries.",
    }


def test_finding_rejects_extra_fields() -> None:
    payload = _base_finding_payload()
    payload["unexpected"] = "value"
    with pytest.raises(ValidationError):
        Finding.model_validate(payload)


def test_finding_validates_line_range() -> None:
    payload = _base_finding_payload()
    payload["start_line"] = 20
    payload["end_line"] = 10
    with pytest.raises(ValidationError):
        Finding.model_validate(payload)


def test_scan_report_is_strict_and_valid() -> None:
    finding = Finding.model_validate(_base_finding_payload())
    report = ScanReport(
        metadata=ScanMetadata(
            repo_path="/tmp/repo",
            scan_started_at=datetime.now(timezone.utc),
            scan_finished_at=datetime.now(timezone.utc),
            model="gpt-4.1-mini",
            top_k=5,
            similarity_threshold=0.2,
            max_chunks=100,
            chunk_size_lines=120,
            repair_retries=1,
        ),
        stats=ScanStats(files_scanned=1, chunks_considered=1, findings_before_dedup=1, findings_after_dedup=1),
        findings=[finding],
    )
    dumped = report.model_dump()
    assert dumped["stats"]["files_scanned"] == 1
    assert dumped["findings"][0]["vuln_type"] == "sql_injection"
