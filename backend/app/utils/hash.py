from __future__ import annotations

import hashlib


def sha256_hexdigest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def code_chunk_id(file_path: str, start_line: int, end_line: int, text: str) -> str:
    payload = f"{file_path}:{start_line}:{end_line}:{text}"
    return sha256_hexdigest(payload)
