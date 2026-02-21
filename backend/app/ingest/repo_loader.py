from __future__ import annotations

from pathlib import Path

from app.config import settings
from app.ingest.file_walker import iter_repo_files


def _read_text_file(path: Path, max_file_size_bytes: int) -> str | None:
    try:
        file_size = path.stat().st_size
    except OSError:
        return None

    if file_size == 0 or file_size > max_file_size_bytes:
        return None

    try:
        raw = path.read_bytes()
    except OSError:
        return None

    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if "\x00" in text:
            return None
        return text
    return None


def collect_files(
    root: str | Path,
    include_extensions: tuple[str, ...] | None = None,
    include_filenames: tuple[str, ...] | None = None,
    exclude_dirs: tuple[str, ...] | None = None,
    exclude_globs: tuple[str, ...] | None = None,
    max_files: int | None = None,
    max_file_size_bytes: int | None = None,
) -> list[dict[str, str]]:
    if include_extensions is None:
        include_extensions = settings.include_extensions
    if include_filenames is None:
        include_filenames = settings.include_filenames
    if exclude_dirs is None:
        exclude_dirs = settings.exclude_dirs
    if exclude_globs is None:
        exclude_globs = settings.exclude_globs
    if max_files is None:
        max_files = settings.max_files
    if max_file_size_bytes is None:
        max_file_size_bytes = settings.max_file_size_bytes

    root_path = Path(root).expanduser().resolve()
    if not root_path.exists():
        raise FileNotFoundError(f"path does not exist: {root_path}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"path is not a directory: {root_path}")

    collected: list[dict[str, str]] = []
    for file_path in iter_repo_files(
        root=root_path,
        include_extensions=include_extensions,
        include_filenames=include_filenames,
        exclude_dirs=exclude_dirs,
        exclude_globs=exclude_globs,
        max_files=max_files,
    ):
        text = _read_text_file(file_path, max_file_size_bytes=max_file_size_bytes)
        if text is None:
            continue
        collected.append({"path": file_path.relative_to(root_path).as_posix(), "text": text})
    return collected
