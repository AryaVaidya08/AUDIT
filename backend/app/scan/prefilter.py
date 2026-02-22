from __future__ import annotations

import re
from pathlib import Path
from typing import Sequence

from app.scan.schema import CodeChunk

_SECRET_PATTERN = re.compile(
    r"""(?ix)
    (\b(api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*["'][^"'\n]{6,}["'])
    |(\bAKIA[0-9A-Z]{16}\b)
    """
)
_SQL_DYNAMIC_PATTERN = re.compile(
    r"""(?ix)
    (
      \b(select|insert|update|delete)\b.{0,140}(\+|format\(|f["']|%\s*\()
    )
    |
    (
      \b(execute|query)\s*\(\s*(f["']|["'][^"']{0,250}["']\s*\+)
    )
    """
)
_EVAL_EXEC_PATTERN = re.compile(r"(?i)\b(eval|exec)\s*\(")
_PATH_TRAVERSAL_PATTERN = re.compile(r"(?i)(\.\./|\.\.\\|path\.join\(|os\.path\.join\(|send_file\(|open\()")

_EXTENSION_WEIGHTS: dict[str, float] = {
    ".py": 0.2,
    ".js": 0.2,
    ".jsx": 0.2,
    ".ts": 0.2,
    ".tsx": 0.2,
    ".java": 0.2,
    ".go": 0.2,
    ".rb": 0.2,
    ".php": 0.2,
    ".cs": 0.2,
    ".cpp": 0.2,
    ".c": 0.2,
    ".h": 0.15,
    ".rs": 0.2,
    ".swift": 0.15,
    ".kt": 0.15,
    ".scala": 0.15,
    ".sh": 0.2,
    ".sql": 0.2,
    ".yaml": 0.05,
    ".yml": 0.05,
    ".json": 0.05,
    ".toml": 0.05,
    ".ini": 0.05,
    ".cfg": 0.05,
    ".env": 0.1,
    ".md": 0.0,
    ".txt": 0.0,
    ".rst": 0.0,
}


def _clamp01(value: float) -> float:
    return min(max(float(value), 0.0), 1.0)


def count_suspicious_hits(text: str) -> int:
    patterns = (_SECRET_PATTERN, _SQL_DYNAMIC_PATTERN, _EVAL_EXEC_PATTERN, _PATH_TRAVERSAL_PATTERN)
    return sum(len(list(pattern.finditer(text))) for pattern in patterns)


def get_extension_weight(file_path: str) -> float:
    suffix = Path(file_path).suffix.lower()
    return _clamp01(_EXTENSION_WEIGHTS.get(suffix, 0.1))


def score_chunk(chunk: CodeChunk, kb_top_score: float, suspicious_hits: int, extension_weight: float) -> float:
    _ = chunk
    kb_signal = _clamp01(kb_top_score)
    suspicious_signal = _clamp01(min(max(suspicious_hits, 0), 6) / 6.0)
    ext_signal = _clamp01(extension_weight)
    score = (kb_signal * 0.55) + (suspicious_signal * 0.35) + (ext_signal * 0.10)
    return _clamp01(score)


def select_candidates(
    chunks: Sequence[CodeChunk],
    kb_scores: Sequence[float],
    max_candidates: int,
    min_score: float,
) -> list[int]:
    if len(chunks) != len(kb_scores):
        raise ValueError("chunks and kb_scores must have the same length")

    if max_candidates <= 0:
        return []

    effective_min_score = _clamp01(min_score)
    scored_indices: list[tuple[float, int]] = []
    for chunk_index, chunk in enumerate(chunks):
        suspicious_hits = count_suspicious_hits(chunk.text)
        extension_weight = get_extension_weight(chunk.file_path)
        score = score_chunk(
            chunk=chunk,
            kb_top_score=kb_scores[chunk_index],
            suspicious_hits=suspicious_hits,
            extension_weight=extension_weight,
        )
        scored_indices.append((score, chunk_index))

    scored_indices.sort(key=lambda item: (-item[0], item[1]))
    selected = [chunk_index for score, chunk_index in scored_indices if score >= effective_min_score]
    return selected[:max_candidates]
