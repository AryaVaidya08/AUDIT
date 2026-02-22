from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
DEFAULT_SCAN_PATH = REPO_ROOT / "test_repo"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.scan.scan_repo import scan_repo


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
    parser.add_argument(
        "--llm-timeout-seconds",
        type=float,
        default=None,
        help="Per LLM call timeout in seconds",
    )
    parser.add_argument(
        "--resume",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Resume from a matching checkpoint when available",
    )
    parser.add_argument(
        "--prefilter-min-score",
        type=float,
        default=None,
        help="Minimum prefilter score to keep a candidate chunk",
    )
    parser.add_argument(
        "--prefilter-max-candidates",
        type=int,
        default=None,
        help="Maximum prefiltered candidates to send to cache/LLM stage",
    )
    parser.add_argument(
        "--max-inflight-llm-calls",
        type=int,
        default=None,
        help="Maximum concurrent in-flight LLM calls for cache misses",
    )
    parser.add_argument(
        "--cache",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable or disable incremental SQLite cache",
    )
    parser.add_argument("--cache-path", type=str, default=None, help="Path to SQLite cache file")
    parser.add_argument("--checkpoint-path", type=str, default=None, help="Path to resume checkpoint JSON")
    parser.add_argument("--model", type=str, default=None, help="LLM model name")
    parser.add_argument("--chunk-size-lines", type=int, default=None, help="Chunk size in lines")
    parser.add_argument(
        "--progress",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Show per-chunk scan progress on stderr",
    )
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    progress_callback = None
    if args.progress:
        progress_callback = lambda message: print(message, file=sys.stderr, flush=True)

    try:
        report = scan_repo(
            path=args.path,
            top_k=args.top_k,
            threshold=args.threshold,
            max_chunks=args.max_chunks,
            repair_retries=args.repair_retries,
            llm_timeout_seconds=args.llm_timeout_seconds,
            resume=args.resume,
            prefilter_min_score=args.prefilter_min_score,
            prefilter_max_candidates=args.prefilter_max_candidates,
            max_inflight_llm_calls=args.max_inflight_llm_calls,
            cache_enabled=args.cache,
            cache_path=args.cache_path,
            checkpoint_path=args.checkpoint_path,
            model=args.model,
            chunk_size_lines=args.chunk_size_lines,
            progress_callback=progress_callback,
        )
    except (FileNotFoundError, NotADirectoryError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(report.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
