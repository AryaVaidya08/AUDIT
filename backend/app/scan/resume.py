from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from app.utils.hash import sha256_hexdigest


@dataclass(frozen=True)
class ResumeCheckpoint:
    run_signature: str
    repo_path: str
    scan_params_signature: str
    candidate_index_hash: str
    next_candidate_offset: int
    partial_stats: dict[str, Any]
    extras: dict[str, Any] = field(default_factory=dict)


def compute_scan_params_signature(params: Mapping[str, Any]) -> str:
    payload = json.dumps(dict(params), sort_keys=True, separators=(",", ":"), default=str)
    return sha256_hexdigest(payload)


def compute_candidate_index_hash(candidate_indices: Sequence[int]) -> str:
    payload = ",".join(str(index) for index in candidate_indices)
    return sha256_hexdigest(payload)


def compute_run_signature(repo_path: str, scan_params_signature: str, candidate_index_hash: str) -> str:
    payload = "\n".join([repo_path, scan_params_signature, candidate_index_hash])
    return sha256_hexdigest(payload)


def _coerce_checkpoint(payload: Mapping[str, Any]) -> ResumeCheckpoint | None:
    required = (
        "run_signature",
        "repo_path",
        "scan_params_signature",
        "candidate_index_hash",
        "next_candidate_offset",
        "partial_stats",
    )
    for key in required:
        if key not in payload:
            return None

    try:
        next_candidate_offset = max(0, int(payload["next_candidate_offset"]))
    except (TypeError, ValueError):
        return None

    partial_stats = payload["partial_stats"]
    if not isinstance(partial_stats, dict):
        return None

    return ResumeCheckpoint(
        run_signature=str(payload["run_signature"]),
        repo_path=str(payload["repo_path"]),
        scan_params_signature=str(payload["scan_params_signature"]),
        candidate_index_hash=str(payload["candidate_index_hash"]),
        next_candidate_offset=next_candidate_offset,
        partial_stats=dict(partial_stats),
        extras={key: value for key, value in payload.items() if key not in required},
    )


def load_checkpoint(path: str | Path) -> ResumeCheckpoint | None:
    checkpoint_path = Path(path).expanduser().resolve()
    if not checkpoint_path.exists() or not checkpoint_path.is_file():
        return None
    try:
        payload = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return _coerce_checkpoint(payload)


def save_checkpoint(path: str | Path, checkpoint: ResumeCheckpoint) -> None:
    checkpoint_path = Path(path).expanduser().resolve()
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "run_signature": checkpoint.run_signature,
        "repo_path": checkpoint.repo_path,
        "scan_params_signature": checkpoint.scan_params_signature,
        "candidate_index_hash": checkpoint.candidate_index_hash,
        "next_candidate_offset": checkpoint.next_candidate_offset,
        "partial_stats": checkpoint.partial_stats,
    }
    payload.update(checkpoint.extras)
    tmp_path = checkpoint_path.with_suffix(checkpoint_path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True), encoding="utf-8")
    tmp_path.replace(checkpoint_path)


def clear_checkpoint(path: str | Path) -> None:
    checkpoint_path = Path(path).expanduser().resolve()
    if checkpoint_path.exists() and checkpoint_path.is_file():
        checkpoint_path.unlink()
