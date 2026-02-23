from __future__ import annotations

from pathlib import Path

from app.config import Settings


def test_runtime_storage_defaults_use_absolute_user_paths(monkeypatch: object) -> None:
    for key in ("CHROMA_PERSIST_DIR", "SCAN_CACHE_PATH", "SCAN_CHECKPOINT_PATH"):
        monkeypatch.delenv(key, raising=False)

    settings = Settings.from_env()
    chroma_path = Path(settings.chroma_persist_dir)
    cache_path = Path(settings.scan_cache_path)
    checkpoint_path = Path(settings.scan_checkpoint_path)

    assert chroma_path.is_absolute()
    assert cache_path.is_absolute()
    assert checkpoint_path.is_absolute()
    assert chroma_path.name == "chroma"
    assert cache_path.name == "scan_cache.sqlite3"
    assert checkpoint_path.name == "scan_resume.json"

