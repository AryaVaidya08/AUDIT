from __future__ import annotations

import os
from dataclasses import dataclass


def _parse_csv(raw: str | None, fallback: tuple[str, ...]) -> tuple[str, ...]:
    if not raw:
        return fallback
    parsed = tuple(item.strip() for item in raw.split(",") if item.strip())
    return parsed or fallback


def _parse_int(raw: str | None, fallback: int) -> int:
    if not raw:
        return fallback
    try:
        return int(raw)
    except ValueError:
        return fallback


def _parse_bool(raw: str | None, fallback: bool) -> bool:
    if raw is None:
        return fallback
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return fallback


@dataclass(frozen=True)
class Settings:
    chunk_size_lines: int
    max_files: int
    max_file_size_bytes: int
    include_extensions: tuple[str, ...]
    include_filenames: tuple[str, ...]
    exclude_dirs: tuple[str, ...]
    exclude_globs: tuple[str, ...]
    kb_dir: str
    chroma_persist_dir: str
    chroma_collection_code_chunks: str
    chroma_collection_security_kb: str
    embedding_model: str
    embedding_batch_size: int
    retrieval_top_k: int
    debug_retrieval: bool

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            chunk_size_lines=_parse_int(os.getenv("CHUNK_SIZE_LINES"), 120),
            max_files=_parse_int(os.getenv("MAX_FILES"), 5000),
            max_file_size_bytes=_parse_int(os.getenv("MAX_FILE_SIZE_BYTES"), 1_000_000),
            include_extensions=_parse_csv(
                os.getenv("INCLUDE_EXTENSIONS"),
                (
                    ".py",
                    ".js",
                    ".jsx",
                    ".ts",
                    ".tsx",
                    ".java",
                    ".go",
                    ".rb",
                    ".php",
                    ".cs",
                    ".cpp",
                    ".c",
                    ".h",
                    ".rs",
                    ".swift",
                    ".kt",
                    ".scala",
                    ".sql",
                    ".sh",
                    ".yaml",
                    ".yml",
                    ".json",
                    ".toml",
                    ".ini",
                    ".cfg",
                    ".env",
                    ".md",
                ),
            ),
            include_filenames=_parse_csv(
                os.getenv("INCLUDE_FILENAMES"),
                (
                    "Dockerfile",
                    "docker-compose.yml",
                    "docker-compose.yaml",
                    "Makefile",
                ),
            ),
            exclude_dirs=_parse_csv(
                os.getenv("EXCLUDE_DIRS"),
                (
                    ".git",
                    ".venv",
                    "venv",
                    "node_modules",
                    "dist",
                    "build",
                    "__pycache__",
                    ".mypy_cache",
                    ".pytest_cache",
                    ".cache",
                    ".chroma",
                ),
            ),
            exclude_globs=_parse_csv(
                os.getenv("EXCLUDE_GLOBS"),
                (
                    "*.min.js",
                    "*.lock",
                    "*.png",
                    "*.jpg",
                    "*.jpeg",
                    "*.gif",
                    "*.svg",
                    "*.pdf",
                    "*.zip",
                    "*.tar",
                    "*.gz",
                    "*.exe",
                    "*.bin",
                ),
            ),
            kb_dir=os.getenv("KB_DIR", "backend/app/scan/kb"),
            chroma_persist_dir=os.getenv("CHROMA_PERSIST_DIR", ".chroma"),
            chroma_collection_code_chunks=os.getenv("CHROMA_COLLECTION_CODE_CHUNKS", "code_chunks"),
            chroma_collection_security_kb=os.getenv("CHROMA_COLLECTION_SECURITY_KB", "security_kb"),
            embedding_model=os.getenv("EMBEDDING_MODEL", "text-embedding-3-small"),
            embedding_batch_size=_parse_int(os.getenv("EMBEDDING_BATCH_SIZE"), 64),
            retrieval_top_k=_parse_int(os.getenv("RETRIEVAL_TOP_K"), 5),
            debug_retrieval=_parse_bool(os.getenv("DEBUG_RETRIEVAL"), False),
        )


settings = Settings.from_env()
