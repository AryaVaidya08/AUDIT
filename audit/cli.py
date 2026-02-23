from __future__ import annotations

import sys
from collections import Counter
from collections.abc import Sequence
from enum import Enum
from pathlib import Path
from typing import Any

import click
import typer

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.scan.scan_repo import scan_repo
from app.scan.schema import Finding, ScanReport

app = typer.Typer(
    add_completion=False,
    no_args_is_help=False,
    help="Audit local repositories for security findings.",
)


@app.callback()
def root() -> None:
    """Command group for audit scan actions."""


class FailOnSeverity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_SEVERITY_SUMMARY_ORDER = ("critical", "high", "medium", "low")
_ROOT_HELP_FLAGS = {"-h", "--help", "--version", "--install-completion", "--show-completion"}


def _severity_value(raw: Any) -> str:
    value = raw.value if hasattr(raw, "value") else raw
    return str(value).strip().lower()


def _normalize_args(raw_args: Sequence[str]) -> list[str]:
    if not raw_args:
        return ["scan", "."]

    if raw_args[0] in {"scan"} | _ROOT_HELP_FLAGS:
        return list(raw_args)
    return ["scan", *raw_args]


def _top_findings(findings: Sequence[Finding], limit: int = 5) -> list[Finding]:
    ranked = sorted(
        findings,
        key=lambda finding: (
            -_SEVERITY_ORDER.get(_severity_value(finding.severity), 0),
            -float(finding.confidence),
            finding.file_path,
            finding.start_line,
            finding.vuln_type.lower(),
        ),
    )
    return ranked[: max(0, limit)]


def _print_summary(report: ScanReport, out_path: Path) -> None:
    counts = Counter(_severity_value(finding.severity) for finding in report.findings)
    ordered_counts = ", ".join(f"{severity}={counts.get(severity, 0)}" for severity in _SEVERITY_SUMMARY_ORDER)
    typer.echo(f"Severity counts: {ordered_counts}")

    top = _top_findings(report.findings, limit=5)
    typer.echo("Top findings (up to 5):")
    if not top:
        typer.echo("(none)")
    else:
        for index, finding in enumerate(top, start=1):
            severity = _severity_value(finding.severity)
            typer.echo(
                f"{index}. [{severity}] {finding.file_path}:{finding.start_line} "
                f"{finding.vuln_type} - {finding.message}"
            )

    typer.echo(f"Full report: {out_path}")


def _should_fail(report: ScanReport, threshold: FailOnSeverity | None) -> bool:
    if threshold is None:
        return False
    threshold_rank = _SEVERITY_ORDER[threshold.value]
    return any(_SEVERITY_ORDER.get(_severity_value(finding.severity), 0) >= threshold_rank for finding in report.findings)


def _resolve_out_path(out: Path) -> Path:
    expanded = out.expanduser()
    if expanded.is_absolute():
        return expanded
    return (Path.cwd() / expanded).resolve()


def _scan_command(
    path: Path,
    out: Path,
    fail_on: FailOnSeverity | None,
    top_k: int | None,
    threshold: float | None,
    max_chunks: int | None,
    repair_retries: int | None,
    llm_timeout_seconds: float | None,
    resume: bool,
    prefilter_min_score: float | None,
    prefilter_max_candidates: int | None,
    max_inflight_llm_calls: int | None,
    cache: bool | None,
    cache_scope: str,
    cache_path: str | None,
    checkpoint_path: str | None,
    model: str | None,
    chunk_size_lines: int | None,
    progress: bool,
) -> int:
    progress_callback = None
    if progress:
        progress_callback = lambda message: print(message, file=sys.stderr, flush=True)

    scan_path = path.expanduser().resolve()
    effective_cache_path = cache_path
    if effective_cache_path is None and cache_scope == "repo":
        effective_cache_path = str(scan_path / ".audit" / "scan_cache.sqlite3")

    try:
        report = scan_repo(
            path=scan_path,
            top_k=top_k,
            threshold=threshold,
            max_chunks=max_chunks,
            repair_retries=repair_retries,
            llm_timeout_seconds=llm_timeout_seconds,
            resume=resume,
            prefilter_min_score=prefilter_min_score,
            prefilter_max_candidates=prefilter_max_candidates,
            max_inflight_llm_calls=max_inflight_llm_calls,
            cache_enabled=cache,
            cache_path=effective_cache_path,
            checkpoint_path=checkpoint_path,
            model=model,
            chunk_size_lines=chunk_size_lines,
            progress_callback=progress_callback,
            heuristic_fallback=True,
        )
    except (FileNotFoundError, NotADirectoryError, ValueError) as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        return 2
    except Exception as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        return 2

    out_path = _resolve_out_path(out)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        typer.echo(f"ERROR: failed to write report at {out_path}: {exc}", err=True)
        return 2

    _print_summary(report=report, out_path=out_path)
    return 1 if _should_fail(report=report, threshold=fail_on) else 0


@app.command("scan")
def scan(
    path: Path = typer.Argument(Path("."), help="Path to repository to scan."),
    out: Path = typer.Option(Path("report.json"), "--out", help="Path to write full JSON scan report."),
    fail_on: FailOnSeverity | None = typer.Option(
        None,
        "--fail-on",
        case_sensitive=False,
        help="Exit with code 1 if any finding is at or above this severity.",
    ),
    top_k: int | None = typer.Option(None, "--top-k", min=1, help="Top KB docs per chunk."),
    threshold: float | None = typer.Option(None, "--threshold", min=0.0, max=1.0, help="Minimum similarity threshold."),
    max_chunks: int | None = typer.Option(None, "--max-chunks", min=1, help="Maximum chunks to consider."),
    repair_retries: int | None = typer.Option(None, "--repair-retries", min=0, help="LLM JSON repair retries."),
    llm_timeout_seconds: float | None = typer.Option(
        None,
        "--llm-timeout-seconds",
        min=1.0,
        help="Per LLM call timeout in seconds.",
    ),
    resume: bool = typer.Option(
        False,
        "--resume/--no-resume",
        help="Resume from a matching checkpoint when available.",
    ),
    prefilter_min_score: float | None = typer.Option(
        None,
        "--prefilter-min-score",
        min=0.0,
        max=1.0,
        help="Minimum prefilter score to keep a candidate chunk.",
    ),
    prefilter_max_candidates: int | None = typer.Option(
        None,
        "--prefilter-max-candidates",
        min=1,
        help="Maximum prefiltered candidates sent to cache/LLM stage.",
    ),
    max_inflight_llm_calls: int | None = typer.Option(
        None,
        "--max-inflight-llm-calls",
        min=1,
        help="Maximum concurrent in-flight LLM calls for cache misses.",
    ),
    cache: bool | None = typer.Option(None, "--cache/--no-cache", help="Enable or disable incremental SQLite cache."),
    cache_scope: str = typer.Option(
        "user",
        "--cache-scope",
        help="Default cache location when --cache-path is not provided. Choices: user, repo.",
    ),
    cache_path: str | None = typer.Option(None, "--cache-path", help="Path to SQLite cache file."),
    checkpoint_path: str | None = typer.Option(None, "--checkpoint-path", help="Path to resume checkpoint JSON."),
    model: str | None = typer.Option(None, "--model", help="LLM model name."),
    chunk_size_lines: int | None = typer.Option(None, "--chunk-size-lines", min=1, help="Chunk size in lines."),
    progress: bool = typer.Option(True, "--progress/--no-progress", help="Show per-chunk scan progress on stderr."),
) -> int:
    if cache_scope not in {"user", "repo"}:
        typer.echo("ERROR: --cache-scope must be either 'user' or 'repo'.", err=True)
        return 2
    return _scan_command(
        path=path,
        out=out,
        fail_on=fail_on,
        top_k=top_k,
        threshold=threshold,
        max_chunks=max_chunks,
        repair_retries=repair_retries,
        llm_timeout_seconds=llm_timeout_seconds,
        resume=resume,
        prefilter_min_score=prefilter_min_score,
        prefilter_max_candidates=prefilter_max_candidates,
        max_inflight_llm_calls=max_inflight_llm_calls,
        cache=cache,
        cache_scope=cache_scope,
        cache_path=cache_path,
        checkpoint_path=checkpoint_path,
        model=model,
        chunk_size_lines=chunk_size_lines,
        progress=progress,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _normalize_args(sys.argv[1:] if argv is None else list(argv))
    try:
        result = app(args=args, prog_name="audit", standalone_mode=False)
    except click.exceptions.Exit as exc:
        return int(exc.exit_code)
    except click.ClickException as exc:
        exc.show()
        return int(exc.exit_code)
    except Exception as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        return 2
    return int(result) if isinstance(result, int) else 0


def entrypoint() -> None:
    raise SystemExit(main())
