from __future__ import annotations

import sqlite3
from pathlib import Path

from app.scan.cache import CacheRecord, ScanCache, build_cache_key, compute_chunk_hash
from app.scan.schema import Finding


def _sample_finding() -> Finding:
    return Finding(
        vuln_type="sql_injection",
        severity="high",
        confidence=0.9,
        references=["cwe-89"],
        file_path="src/app.py",
        start_line=10,
        end_line=10,
        message="Possible SQL injection.",
        evidence="query = f\"SELECT ... {user_input}\"",
        recommendation="Use parameterized queries.",
    )


def test_scan_cache_round_trip_returns_validated_findings(tmp_path: Path) -> None:
    cache_path = tmp_path / "scan_cache.sqlite3"
    cache = ScanCache(cache_path)
    cache.ensure_schema()

    chunk_hash = compute_chunk_hash("print('x')")
    cache_key = build_cache_key(
        repo_path=str(tmp_path / "repo"),
        file_path="src/app.py",
        start_line=1,
        end_line=20,
        chunk_hash=chunk_hash,
        model="gpt-4.1-mini",
        prompt_version="v1",
    )
    cache.put_many(
        [
            CacheRecord(
                cache_key=cache_key,
                repo_path=str(tmp_path / "repo"),
                file_path="src/app.py",
                start_line=1,
                end_line=20,
                chunk_hash=chunk_hash,
                model="gpt-4.1-mini",
                prompt_version="v1",
                findings=[_sample_finding()],
            )
        ]
    )

    hits = cache.get_many([cache_key])
    assert cache_key in hits
    assert len(hits[cache_key]) == 1
    assert hits[cache_key][0].vuln_type == "sql_injection"


def test_scan_cache_skips_invalid_cached_findings_payload(tmp_path: Path) -> None:
    cache_path = tmp_path / "scan_cache.sqlite3"
    cache = ScanCache(cache_path)
    cache.ensure_schema()

    bad_key = "bad-key"
    with sqlite3.connect(cache_path) as conn:
        conn.execute(
            """
            INSERT INTO scan_cache (
                cache_key, repo_path, file_path, start_line, end_line, chunk_hash, model, prompt_version, findings_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                bad_key,
                str(tmp_path / "repo"),
                "src/app.py",
                1,
                20,
                "chunkhash",
                "gpt-4.1-mini",
                "v1",
                '{"not":"a-list"}',
                "2026-01-01T00:00:00+00:00",
            ),
        )
        conn.commit()

    hits = cache.get_many([bad_key])
    assert bad_key not in hits
