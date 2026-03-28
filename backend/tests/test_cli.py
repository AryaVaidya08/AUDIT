from __future__ import annotations

from datetime import datetime, timezone
import re
from pathlib import Path
from types import SimpleNamespace

import audit.cli as cli_module
from audit.cli import main as cli_main
from app.scan.schema import Finding, ScanMetadata, ScanReport, ScanStats

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_REPO = REPO_ROOT / "demo_vuln_repo"


def _read_report(path: Path) -> ScanReport:
    return ScanReport.model_validate_json(path.read_text(encoding="utf-8"))


def _sample_report(repo_path: Path, *, severity: str = "medium") -> ScanReport:
    now = datetime.now(timezone.utc)
    return ScanReport(
        metadata=ScanMetadata(
            repo_path=str(repo_path),
            scan_started_at=now,
            scan_finished_at=now,
            model="gpt-4.1-mini",
            top_k=5,
            similarity_threshold=0.2,
            max_chunks=300,
            chunk_size_lines=120,
            repair_retries=1,
        ),
        stats=ScanStats(
            files_scanned=1,
            chunks_considered=1,
            chunks_prefiltered=1,
            chunks_sent_to_llm=1,
            findings_before_dedup=1,
            findings_after_dedup=1,
        ),
        findings=[
            Finding(
                vuln_type="sql_injection",
                title="SQL Injection",
                rule_id="SQLI.DYNAMIC_QUERY",
                severity=severity,
                confidence=0.91,
                references=["cwe-89"],
                file_path="src/demo.py",
                start_line=10,
                end_line=10,
                message="Potential SQL injection through dynamic query construction.",
                evidence="query = f\"SELECT * FROM users WHERE id = {user_id}\"",
                recommendation="Use parameterized queries.",
            )
        ],
        errors=[],
    )


def test_default_command_audit_dot_writes_json_and_summary(
    monkeypatch: object,
    capsys: object,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(DEMO_REPO)
    out_path = tmp_path / "default-report.json"
    report = _sample_report(DEMO_REPO)

    monkeypatch.setattr(cli_module, "scan_repo", lambda **_: report)

    exit_code = cli_main([".", "--out", str(out_path), "--no-progress"])

    assert exit_code == 0
    assert out_path.exists()

    report = _read_report(out_path)
    assert len(report.findings) > 0

    captured = capsys.readouterr()
    assert "Severity counts:" in captured.out
    assert "Top findings (up to 5):" in captured.out
    assert "SQL Injection - Potential SQL injection through dynamic query construction." in captured.out
    assert "sql_injection" not in captured.out
    assert '"metadata"' not in captured.out
    top_lines = [line for line in captured.out.splitlines() if re.match(r"^\d+\.\s", line)]
    assert len(top_lines) <= 5


def test_explicit_scan_subcommand_writes_equivalent_report(
    monkeypatch: object,
    tmp_path: Path,
) -> None:
    report = _sample_report(DEMO_REPO)
    monkeypatch.setattr(cli_module, "scan_repo", lambda **_: report)

    default_report_path = tmp_path / "default-report.json"
    explicit_report_path = tmp_path / "explicit-report.json"

    default_code = cli_main([str(DEMO_REPO), "--out", str(default_report_path), "--no-progress"])
    explicit_code = cli_main(["scan", str(DEMO_REPO), "--out", str(explicit_report_path), "--no-progress"])

    assert default_code == 0
    assert explicit_code == 0
    assert default_report_path.exists()
    assert explicit_report_path.exists()

    default_report = _read_report(default_report_path)
    explicit_report = _read_report(explicit_report_path)
    assert [finding.model_dump() for finding in default_report.findings] == [
        finding.model_dump() for finding in explicit_report.findings
    ]


def test_fail_on_high_flips_exit_code(monkeypatch: object, tmp_path: Path) -> None:
    report = _sample_report(DEMO_REPO, severity="high")
    monkeypatch.setattr(cli_module, "scan_repo", lambda **_: report)
    out_path = tmp_path / "fail-on-report.json"

    exit_code = cli_main(
        [
            str(DEMO_REPO),
            "--out",
            str(out_path),
            "--fail-on",
            "high",
            "--no-progress",
        ]
    )

    assert exit_code == 1
    assert out_path.exists()


def test_missing_api_key_returns_runtime_error(
    monkeypatch: object,
    capsys: object,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    out_path = tmp_path / "error-report.json"
    monkeypatch.setattr(
        cli_module,
        "scan_repo",
        lambda **_: (_ for _ in ()).throw(
            RuntimeError(
                "LLM is not available: the openai package is not installed or OPENAI_API_KEY is not set. "
                "Install openai and set your API key to use this tool."
            )
        ),
    )

    exit_code = cli_main([str(DEMO_REPO), "--out", str(out_path), "--no-progress"])

    assert exit_code == 2
    assert not out_path.exists()
    captured = capsys.readouterr()
    assert "LLM is not available" in captured.err


def test_no_candidate_stage_flag_is_forwarded(monkeypatch: object, tmp_path: Path) -> None:
    captured_args: dict[str, object] = {}

    def _fake_scan_repo(**kwargs: object) -> ScanReport:
        captured_args.update(kwargs)
        return _sample_report(DEMO_REPO)

    monkeypatch.setattr(cli_module, "scan_repo", _fake_scan_repo)

    out_path = tmp_path / "candidate-stage-report.json"
    exit_code = cli_main([str(DEMO_REPO), "--out", str(out_path), "--no-candidate-stage", "--no-progress"])

    assert exit_code == 0
    assert out_path.exists()
    assert captured_args["candidate_stage_enabled"] is False


def test_dev_clear_cache_removes_only_repo_local_artifacts_by_default(
    monkeypatch: object,
    capsys: object,
    tmp_path: Path,
) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    repo_cache_dir = repo_path / ".audit"
    repo_cache_dir.mkdir()
    (repo_cache_dir / "scan_cache.sqlite3").write_text("cache", encoding="utf-8")
    (repo_cache_dir / "scan_resume.json").write_text("resume", encoding="utf-8")
    (repo_cache_dir / "chroma").mkdir()

    shared_cache_dir = tmp_path / "shared-cache"
    shared_cache_dir.mkdir()
    scan_cache_path = shared_cache_dir / "scan_cache.sqlite3"
    checkpoint_path = shared_cache_dir / "scan_resume.json"
    chroma_dir = shared_cache_dir / "chroma"
    scan_cache_path.write_text("cache", encoding="utf-8")
    checkpoint_path.write_text("resume", encoding="utf-8")
    chroma_dir.mkdir()
    (chroma_dir / "segment.bin").write_text("payload", encoding="utf-8")

    monkeypatch.setattr(
        cli_module,
        "settings",
        SimpleNamespace(
            scan_cache_path=str(scan_cache_path),
            scan_checkpoint_path=str(checkpoint_path),
            chroma_persist_dir=str(chroma_dir),
        ),
    )

    exit_code = cli_main(["dev", "clear-cache", str(repo_path)])

    assert exit_code == 0
    assert not repo_cache_dir.exists()
    assert scan_cache_path.exists()
    assert checkpoint_path.exists()
    assert chroma_dir.exists()

    captured = capsys.readouterr()
    assert "Removed cache artifacts:" in captured.out
    assert str(repo_cache_dir / "scan_cache.sqlite3") in captured.out
    assert str(scan_cache_path) not in captured.out


def test_dev_clear_cache_with_shared_removes_shared_and_repo_cache_artifacts(
    monkeypatch: object,
    capsys: object,
    tmp_path: Path,
) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    repo_cache_dir = repo_path / ".audit"
    repo_cache_dir.mkdir()
    (repo_cache_dir / "scan_cache.sqlite3").write_text("cache", encoding="utf-8")
    (repo_cache_dir / "scan_resume.json").write_text("resume", encoding="utf-8")
    (repo_cache_dir / "chroma").mkdir()

    shared_cache_dir = tmp_path / "shared-cache"
    shared_cache_dir.mkdir()
    scan_cache_path = shared_cache_dir / "scan_cache.sqlite3"
    checkpoint_path = shared_cache_dir / "scan_resume.json"
    chroma_dir = shared_cache_dir / "chroma"
    scan_cache_path.write_text("cache", encoding="utf-8")
    checkpoint_path.write_text("resume", encoding="utf-8")
    chroma_dir.mkdir()
    (chroma_dir / "segment.bin").write_text("payload", encoding="utf-8")

    monkeypatch.setattr(
        cli_module,
        "settings",
        SimpleNamespace(
            scan_cache_path=str(scan_cache_path),
            scan_checkpoint_path=str(checkpoint_path),
            chroma_persist_dir=str(chroma_dir),
        ),
    )

    exit_code = cli_main(["dev", "clear-cache", str(repo_path), "--shared"])

    assert exit_code == 0
    assert not scan_cache_path.exists()
    assert not checkpoint_path.exists()
    assert not chroma_dir.exists()
    assert not repo_cache_dir.exists()

    captured = capsys.readouterr()
    assert "Removed cache artifacts:" in captured.out
    assert str(scan_cache_path) in captured.out
    assert str(repo_cache_dir / "scan_cache.sqlite3") in captured.out


def test_dev_clear_cache_reports_when_nothing_exists(
    monkeypatch: object,
    capsys: object,
    tmp_path: Path,
) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    monkeypatch.setattr(
        cli_module,
        "settings",
        SimpleNamespace(
            scan_cache_path=str(tmp_path / "missing-scan-cache.sqlite3"),
            scan_checkpoint_path=str(tmp_path / "missing-scan-resume.json"),
            chroma_persist_dir=str(tmp_path / "missing-chroma"),
        ),
    )

    exit_code = cli_main(["dev", "clear-cache", str(repo_path)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "No cache artifacts found." in captured.out


def test_dev_clear_cache_resolves_relative_configured_paths_from_target_repo(
    monkeypatch: object,
    capsys: object,
    tmp_path: Path,
) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    launch_dir = tmp_path / "launcher"
    launch_dir.mkdir()
    monkeypatch.chdir(launch_dir)

    chroma_dir = repo_path / ".chroma"
    chroma_dir.mkdir()
    (chroma_dir / "segment.bin").write_text("payload", encoding="utf-8")

    monkeypatch.setattr(
        cli_module,
        "settings",
        SimpleNamespace(
            scan_cache_path=".audit/scan_cache.sqlite3",
            scan_checkpoint_path=".audit/scan_resume.json",
            chroma_persist_dir=".chroma",
        ),
    )

    exit_code = cli_main(["dev", "clear-cache", str(repo_path)])

    assert exit_code == 0
    assert not chroma_dir.exists()
    assert not (launch_dir / ".chroma").exists()
    captured = capsys.readouterr()
    assert str(chroma_dir) in captured.out
