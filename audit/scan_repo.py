from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
DEFAULT_SCAN_PATH = REPO_ROOT / "test_repo"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.scan.scan_repo import scan_repo  # noqa: E402


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run local repository security scan.")
    parser.add_argument(
        "path",
        nargs="?",
        default=str(DEFAULT_SCAN_PATH),
        help=f"Path to repository to scan (default: {DEFAULT_SCAN_PATH})",
    )
    parser.add_argument("--top-k", type=int, default=None, help="Top KB docs per chunk")
    parser.add_argument("--threshold", type=float, default=None, help="Minimum similarity threshold")
    parser.add_argument("--max-chunks", type=int, default=None, help="Maximum chunks to consider")
    parser.add_argument("--repair-retries", type=int, default=None, help="LLM JSON repair retries")
    parser.add_argument("--model", type=str, default=None, help="LLM model name")
    parser.add_argument("--chunk-size-lines", type=int, default=None, help="Chunk size in lines")
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    try:
        report = scan_repo(
            path=args.path,
            top_k=args.top_k,
            threshold=args.threshold,
            max_chunks=args.max_chunks,
            repair_retries=args.repair_retries,
            model=args.model,
            chunk_size_lines=args.chunk_size_lines,
        )
    except (FileNotFoundError, NotADirectoryError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(report.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
