from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import zipfile

PROJECT_NAME = "audit-local-scanner"
PROJECT_VERSION = "0.1.0"
SUMMARY = "Local-first security scanning CLI with deterministic fallback heuristics."
REQUIRES_PYTHON = ">=3.10"
REQUIRES_DIST = (
    "pydantic>=2.6,<3",
    "typer>=0.12,<1",
)
ENTRYPOINT = "audit-code = audit.cli:entrypoint"


def _repo_root() -> Path:
    return Path(__file__).resolve().parent


def _dist_name() -> str:
    return PROJECT_NAME.replace("-", "_")


def _dist_info_dir() -> str:
    return f"{_dist_name()}-{PROJECT_VERSION}.dist-info"


def _wheel_name() -> str:
    return f"{_dist_name()}-{PROJECT_VERSION}-py3-none-any.whl"


def _metadata_text() -> str:
    lines = [
        "Metadata-Version: 2.1",
        f"Name: {PROJECT_NAME}",
        f"Version: {PROJECT_VERSION}",
        f"Summary: {SUMMARY}",
        f"Requires-Python: {REQUIRES_PYTHON}",
    ]
    for requirement in REQUIRES_DIST:
        lines.append(f"Requires-Dist: {requirement}")
    return "\n".join(lines) + "\n"


def _wheel_text() -> str:
    return "\n".join(
        [
            "Wheel-Version: 1.0",
            "Generator: audit_build_backend",
            "Root-Is-Purelib: true",
            "Tag: py3-none-any",
            "",
        ]
    )


def _entry_points_text() -> str:
    return "[console_scripts]\n" + ENTRYPOINT + "\n"


def _record_row(path: str, payload: bytes) -> str:
    digest = hashlib.sha256(payload).digest()
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"{path},sha256={encoded},{len(payload)}"


def _write_metadata_tree(target_dir: Path) -> str:
    dist_info = target_dir / _dist_info_dir()
    dist_info.mkdir(parents=True, exist_ok=True)
    (dist_info / "METADATA").write_text(_metadata_text(), encoding="utf-8")
    (dist_info / "WHEEL").write_text(_wheel_text(), encoding="utf-8")
    (dist_info / "entry_points.txt").write_text(_entry_points_text(), encoding="utf-8")
    (dist_info / "RECORD").write_text("", encoding="utf-8")
    return dist_info.name


def _iter_audit_package_files() -> list[tuple[str, bytes]]:
    root = _repo_root() / "audit"
    collected: list[tuple[str, bytes]] = []
    for file_path in sorted(root.rglob("*")):
        if not file_path.is_file():
            continue
        relative = file_path.relative_to(_repo_root()).as_posix()
        collected.append((relative, file_path.read_bytes()))
    return collected


def _build_wheel_impl(wheel_directory: str, editable: bool) -> str:
    wheel_dir = Path(wheel_directory)
    wheel_dir.mkdir(parents=True, exist_ok=True)
    wheel_path = wheel_dir / _wheel_name()
    dist_info = _dist_info_dir()
    record_rows: list[str] = []

    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as wheel:
        def add_file(path: str, payload: bytes) -> None:
            wheel.writestr(path, payload)
            record_rows.append(_record_row(path, payload))

        if editable:
            repo_path = os.fspath(_repo_root())
            add_file(f"{_dist_name()}.pth", (repo_path + "\n").encode("utf-8"))
        else:
            for path, payload in _iter_audit_package_files():
                add_file(path, payload)

        add_file(f"{dist_info}/METADATA", _metadata_text().encode("utf-8"))
        add_file(f"{dist_info}/WHEEL", _wheel_text().encode("utf-8"))
        add_file(f"{dist_info}/entry_points.txt", _entry_points_text().encode("utf-8"))

        record_path = f"{dist_info}/RECORD"
        record_text = "\n".join(record_rows + [f"{record_path},,"]) + "\n"
        wheel.writestr(record_path, record_text.encode("utf-8"))

    return wheel_path.name


def _supported_features() -> list[str]:
    return ["build_editable"]


def get_requires_for_build_wheel(config_settings: dict[str, str] | None = None) -> list[str]:
    _ = config_settings
    return []


def get_requires_for_build_editable(config_settings: dict[str, str] | None = None) -> list[str]:
    _ = config_settings
    return []


def prepare_metadata_for_build_wheel(
    metadata_directory: str,
    config_settings: dict[str, str] | None = None,
) -> str:
    _ = config_settings
    target_dir = Path(metadata_directory)
    target_dir.mkdir(parents=True, exist_ok=True)
    return _write_metadata_tree(target_dir)


def prepare_metadata_for_build_editable(
    metadata_directory: str,
    config_settings: dict[str, str] | None = None,
) -> str:
    return prepare_metadata_for_build_wheel(metadata_directory=metadata_directory, config_settings=config_settings)


def build_wheel(
    wheel_directory: str,
    config_settings: dict[str, str] | None = None,
    metadata_directory: str | None = None,
) -> str:
    _ = (config_settings, metadata_directory)
    return _build_wheel_impl(wheel_directory=wheel_directory, editable=False)


def build_editable(
    wheel_directory: str,
    config_settings: dict[str, str] | None = None,
    metadata_directory: str | None = None,
) -> str:
    _ = (config_settings, metadata_directory)
    return _build_wheel_impl(wheel_directory=wheel_directory, editable=True)
