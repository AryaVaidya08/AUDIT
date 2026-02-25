#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform as platform_lib
import shutil
import subprocess
import sys


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the AUDIT standalone binary via PyInstaller.")
    parser.add_argument("--platform", required=True, choices=("darwin", "linux", "windows"))
    parser.add_argument("--arch", required=True, choices=("arm64", "x64"))
    parser.add_argument("--dist-dir", default="dist", help="Directory where built binaries are written.")
    parser.add_argument("--work-dir", default="build/pyinstaller", help="Directory for PyInstaller build intermediates.")
    parser.add_argument("--clean", action="store_true", help="Delete prior dist/work directories before building.")
    return parser.parse_args()


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _default_binary_name() -> str:
    return "audit.exe" if os.name == "nt" else "audit"


def main() -> int:
    args = _parse_args()
    root = _project_root()
    dist_dir = (root / args.dist_dir).resolve()
    work_dir = (root / args.work_dir).resolve()
    spec_dir = (work_dir / "spec").resolve()
    entrypoint = root / "audit" / "__main__.py"
    backend_dir = root / "backend"
    backend_app_dir = backend_dir / "app"

    if not entrypoint.exists():
        raise SystemExit(f"Entry point not found: {entrypoint}")
    if not backend_app_dir.exists():
        raise SystemExit(f"Backend app directory not found: {backend_app_dir}")

    if args.clean:
        shutil.rmtree(dist_dir, ignore_errors=True)
        shutil.rmtree(work_dir, ignore_errors=True)

    dist_dir.mkdir(parents=True, exist_ok=True)
    spec_dir.mkdir(parents=True, exist_ok=True)

    data_mapping = f"{backend_app_dir}{os.pathsep}backend/app"
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name",
        "audit",
        "--distpath",
        str(dist_dir),
        "--workpath",
        str(work_dir),
        "--specpath",
        str(spec_dir),
        "--paths",
        str(backend_dir),
        "--add-data",
        data_mapping,
        str(entrypoint),
    ]

    print(f"[build] platform={args.platform} arch={args.arch}")
    print("[build] running:", " ".join(command))
    subprocess.run(command, cwd=root, check=True)

    binary_path = dist_dir / _default_binary_name()
    if not binary_path.exists():
        alt_path = dist_dir / "audit"
        if alt_path.exists():
            binary_path = alt_path
        else:
            raise SystemExit(f"Built binary was not found in {dist_dir}")

    metadata = {
        "target_platform": args.platform,
        "target_arch": args.arch,
        "host_platform": sys.platform,
        "host_machine": platform_lib.machine(),
        "binary_path": str(binary_path),
    }
    metadata_path = dist_dir / "build-metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(f"[build] wrote metadata: {metadata_path}")
    print(f"[build] binary ready: {binary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
