from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterator, Sequence
from pathlib import Path


def _matches_glob(path: Path, root: Path, patterns: Sequence[str]) -> bool:
    relative = path.relative_to(root).as_posix()
    filename = path.name
    for pattern in patterns:
        if fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(filename, pattern):
            return True
    return False


def _is_included(
    path: Path,
    root: Path,
    include_extensions: Sequence[str],
    include_filenames: Sequence[str],
    exclude_globs: Sequence[str],
) -> bool:
    if _matches_glob(path, root, exclude_globs):
        return False
    if path.name in include_filenames:
        return True
    return path.suffix.lower() in include_extensions


def iter_repo_files(
    root: Path,
    include_extensions: Sequence[str],
    include_filenames: Sequence[str],
    exclude_dirs: Sequence[str],
    exclude_globs: Sequence[str],
    max_files: int,
) -> Iterator[Path]:
    normalized_excluded_dirs = {value.lower() for value in exclude_dirs}
    emitted = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in normalized_excluded_dirs]

        for name in filenames:
            file_path = Path(dirpath) / name
            if not _is_included(
                path=file_path,
                root=root,
                include_extensions=include_extensions,
                include_filenames=include_filenames,
                exclude_globs=exclude_globs,
            ):
                continue

            yield file_path
            emitted += 1
            if emitted >= max_files:
                return
