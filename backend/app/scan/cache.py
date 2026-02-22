from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

from app.scan.schema import Finding
from app.utils.hash import sha256_hexdigest


@dataclass(frozen=True)
class CacheRecord:
    cache_key: str
    repo_path: str
    file_path: str
    start_line: int
    end_line: int
    chunk_hash: str
    model: str
    prompt_version: str
    findings: list[Finding]


def build_cache_key(
    repo_path: str,
    file_path: str,
    start_line: int,
    end_line: int,
    chunk_hash: str,
    model: str,
    prompt_version: str,
) -> str:
    payload = "\n".join(
        [
            repo_path,
            file_path,
            str(start_line),
            str(end_line),
            chunk_hash,
            model,
            prompt_version,
        ]
    )
    return sha256_hexdigest(payload)


def compute_chunk_hash(text: str) -> str:
    return sha256_hexdigest(text)


def _batched(items: Sequence[str], batch_size: int = 500) -> Iterable[list[str]]:
    for index in range(0, len(items), batch_size):
        yield list(items[index : index + batch_size])


class ScanCache:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path).expanduser().resolve()

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(self.db_path), timeout=30.0)
        connection.row_factory = sqlite3.Row
        return connection

    def ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_cache (
                    cache_key TEXT PRIMARY KEY,
                    repo_path TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    start_line INTEGER NOT NULL,
                    end_line INTEGER NOT NULL,
                    chunk_hash TEXT NOT NULL,
                    model TEXT NOT NULL,
                    prompt_version TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS scan_cache_lookup_idx
                ON scan_cache (repo_path, file_path, start_line, end_line, model, prompt_version)
                """
            )
            conn.commit()

    def get_many(self, keys: Sequence[str]) -> dict[str, list[Finding]]:
        if not keys:
            return {}

        unique_keys = list(dict.fromkeys(keys))
        found: dict[str, list[Finding]] = {}
        with self._connect() as conn:
            for batch in _batched(unique_keys):
                placeholders = ",".join("?" for _ in batch)
                query = f"SELECT cache_key, findings_json FROM scan_cache WHERE cache_key IN ({placeholders})"
                rows = conn.execute(query, batch).fetchall()
                for row in rows:
                    cache_key = str(row["cache_key"])
                    findings_json = str(row["findings_json"])
                    try:
                        parsed = json.loads(findings_json)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(parsed, list):
                        continue
                    findings: list[Finding] = []
                    is_valid = True
                    for item in parsed:
                        try:
                            findings.append(Finding.model_validate(item))
                        except Exception:
                            is_valid = False
                            break
                    if is_valid:
                        found[cache_key] = findings
        return found

    def put_many(self, records: Sequence[CacheRecord]) -> None:
        if not records:
            return

        now_text = datetime.now(timezone.utc).isoformat()
        payload = [
            (
                record.cache_key,
                record.repo_path,
                record.file_path,
                record.start_line,
                record.end_line,
                record.chunk_hash,
                record.model,
                record.prompt_version,
                json.dumps([finding.model_dump() for finding in record.findings], ensure_ascii=True),
                now_text,
            )
            for record in records
        ]
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO scan_cache (
                    cache_key,
                    repo_path,
                    file_path,
                    start_line,
                    end_line,
                    chunk_hash,
                    model,
                    prompt_version,
                    findings_json,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    repo_path=excluded.repo_path,
                    file_path=excluded.file_path,
                    start_line=excluded.start_line,
                    end_line=excluded.end_line,
                    chunk_hash=excluded.chunk_hash,
                    model=excluded.model,
                    prompt_version=excluded.prompt_version,
                    findings_json=excluded.findings_json,
                    updated_at=excluded.updated_at
                """
                ,
                payload,
            )
            conn.commit()
