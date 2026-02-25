#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import shutil

ASSET_NAME_BY_TARGET: dict[tuple[str, str], str] = {
    ("darwin", "arm64"): "audit-darwin-arm64",
    ("darwin", "x64"): "audit-darwin-x64",
    ("linux", "x64"): "audit-linux-x64",
    ("windows", "x64"): "audit-windows-x64.exe",
}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare AUDIT release assets and checksums.")
    parser.add_argument("--platform", choices=("darwin", "linux", "windows"))
    parser.add_argument("--arch", choices=("arm64", "x64"))
    parser.add_argument("--dist-dir", default="dist")
    parser.add_argument("--release-dir", default="release")
    parser.add_argument("--binary-path", help="Optional explicit path to the built binary to package.")
    args = parser.parse_args()

    if (args.platform is None) != (args.arch is None):
        parser.error("--platform and --arch must be provided together.")
    return args


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _resolve_asset_name(platform: str, arch: str) -> str:
    key = (platform, arch)
    if key not in ASSET_NAME_BY_TARGET:
        choices = ", ".join(f"{k[0]}-{k[1]}" for k in sorted(ASSET_NAME_BY_TARGET))
        raise SystemExit(f"Unsupported target '{platform}-{arch}'. Supported targets: {choices}")
    return ASSET_NAME_BY_TARGET[key]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_checksums(release_dir: Path) -> Path:
    binaries = sorted(
        [path for path in release_dir.iterdir() if path.is_file() and path.name in set(ASSET_NAME_BY_TARGET.values())],
        key=lambda item: item.name,
    )
    if not binaries:
        raise SystemExit(f"No packaged binaries found in {release_dir}")

    output_path = release_dir / "audit-checksums.txt"
    lines = [f"{_sha256(binary)}  {binary.name}" for binary in binaries]
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[package] checksums file written: {output_path}")
    return output_path


def _copy_binary(
    *,
    dist_dir: Path,
    release_dir: Path,
    platform: str,
    arch: str,
    explicit_binary_path: str | None,
) -> Path:
    asset_name = _resolve_asset_name(platform, arch)

    if explicit_binary_path:
        source = Path(explicit_binary_path).expanduser().resolve()
    else:
        source_name = "audit.exe" if platform == "windows" else "audit"
        source = (dist_dir / source_name).resolve()

    if not source.exists():
        raise SystemExit(f"Expected built binary was not found: {source}")

    destination = release_dir / asset_name
    shutil.copy2(source, destination)
    print(f"[package] copied {source} -> {destination}")
    return destination


def main() -> int:
    args = _parse_args()
    root = _project_root()
    dist_dir = (root / args.dist_dir).resolve()
    release_dir = (root / args.release_dir).resolve()
    release_dir.mkdir(parents=True, exist_ok=True)

    if args.platform and args.arch:
        _copy_binary(
            dist_dir=dist_dir,
            release_dir=release_dir,
            platform=args.platform,
            arch=args.arch,
            explicit_binary_path=args.binary_path,
        )

    _write_checksums(release_dir=release_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
