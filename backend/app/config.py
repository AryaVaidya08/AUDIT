from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

_APP_CACHE_DIR_NAME = "audit"


def _default_user_cache_dir(app_name: str = _APP_CACHE_DIR_NAME) -> Path:
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    elif os.name == "nt":
        local_app_data = os.getenv("LOCALAPPDATA")
        base = Path(local_app_data).expanduser() if local_app_data else Path.home() / "AppData" / "Local"
    else:
        xdg_cache_home = os.getenv("XDG_CACHE_HOME")
        base = Path(xdg_cache_home).expanduser() if xdg_cache_home else Path.home() / ".cache"
    return (base / app_name).expanduser().resolve()


def _parse_env_line(raw_line: str) -> tuple[str, str] | None:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("export "):
        line = line[len("export ") :].strip()
    if "=" not in line:
        return None
    key, value = line.split("=", 1)
    key = key.strip()
    if not key:
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    return key, value


def _load_env_file(path: Path, original_keys: set[str], override: bool) -> None:
    if not path.exists() or not path.is_file():
        return
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return

    for raw_line in lines:
        parsed = _parse_env_line(raw_line)
        if parsed is None:
            continue
        key, value = parsed
        if key in original_keys:
            continue
        if not override and key in os.environ:
            continue
        os.environ[key] = value


def _autoload_repo_env() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    original_keys = set(os.environ.keys())
    _load_env_file(repo_root / ".env", original_keys=original_keys, override=False)
    _load_env_file(repo_root / ".env.local", original_keys=original_keys, override=True)


_autoload_repo_env()


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


def _parse_float(raw: str | None, fallback: float) -> float:
    if not raw:
        return fallback
    try:
        return float(raw)
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
    scan_model: str
    scan_top_k: int
    scan_similarity_threshold: float
    scan_max_chunks: int
    scan_repair_retries: int
    scan_prefilter_enabled: bool
    scan_prefilter_min_score: float
    scan_prefilter_max_candidates: int
    scan_cache_enabled: bool
    scan_cache_path: str
    scan_max_inflight_llm_calls: int
    scan_checkpoint_path: str
    scan_checkpoint_every: int
    scan_llm_timeout_seconds: float

    @classmethod
    def from_env(cls) -> "Settings":
        default_cache_dir = _default_user_cache_dir()
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
                    ".audit",
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
                    "report.json",
                    "*.report.json",
                    "scan_cache.sqlite3",
                    "scan_resume.json",
                ),
            ),
            kb_dir=os.getenv("KB_DIR", "backend/app/scan/kb"),
            chroma_persist_dir=os.getenv("CHROMA_PERSIST_DIR", str(default_cache_dir / "chroma")),
            chroma_collection_code_chunks=os.getenv("CHROMA_COLLECTION_CODE_CHUNKS", "code_chunks"),
            chroma_collection_security_kb=os.getenv("CHROMA_COLLECTION_SECURITY_KB", "security_kb"),
            embedding_model=os.getenv("EMBEDDING_MODEL", "text-embedding-3-small"),
            embedding_batch_size=_parse_int(os.getenv("EMBEDDING_BATCH_SIZE"), 64),
            retrieval_top_k=_parse_int(os.getenv("RETRIEVAL_TOP_K"), 5),
            debug_retrieval=_parse_bool(os.getenv("DEBUG_RETRIEVAL"), False),
            scan_model=os.getenv("SCAN_MODEL", "gpt-4.1-mini"),
            scan_top_k=_parse_int(os.getenv("SCAN_TOP_K"), 5),
            scan_similarity_threshold=_parse_float(os.getenv("SCAN_SIMILARITY_THRESHOLD"), 0.2),
            scan_max_chunks=_parse_int(os.getenv("SCAN_MAX_CHUNKS"), 300),
            scan_repair_retries=_parse_int(os.getenv("SCAN_REPAIR_RETRIES"), 1),
            scan_prefilter_enabled=_parse_bool(os.getenv("SCAN_PREFILTER_ENABLED"), True),
            scan_prefilter_min_score=_parse_float(os.getenv("SCAN_PREFILTER_MIN_SCORE"), 0.2),
            scan_prefilter_max_candidates=_parse_int(os.getenv("SCAN_PREFILTER_MAX_CANDIDATES"), 200),
            scan_cache_enabled=_parse_bool(os.getenv("SCAN_CACHE_ENABLED"), True),
            scan_cache_path=os.getenv("SCAN_CACHE_PATH", str(default_cache_dir / "scan_cache.sqlite3")),
            scan_max_inflight_llm_calls=_parse_int(os.getenv("SCAN_MAX_INFLIGHT_LLM_CALLS"), 4),
            scan_checkpoint_path=os.getenv("SCAN_CHECKPOINT_PATH", str(default_cache_dir / "scan_resume.json")),
            scan_checkpoint_every=_parse_int(os.getenv("SCAN_CHECKPOINT_EVERY"), 5),
            scan_llm_timeout_seconds=_parse_float(os.getenv("SCAN_LLM_TIMEOUT_SECONDS"), 20.0),
        )


settings = Settings.from_env()
