from __future__ import annotations

import re
from pathlib import Path

from audit.cli import main as cli_main
from app.scan.schema import ScanReport

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_REPO = REPO_ROOT / "demo_vuln_repo"


def _read_report(path: Path) -> ScanReport:
    return ScanReport.model_validate_json(path.read_text(encoding="utf-8"))


def test_default_command_audit_dot_writes_json_and_summary(
    monkeypatch: object,
    capsys: object,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.chdir(DEMO_REPO)
    out_path = tmp_path / "default-report.json"

    exit_code = cli_main([".", "--out", str(out_path), "--no-progress"])

    assert exit_code == 0
    assert out_path.exists()

    report = _read_report(out_path)
    assert len(report.findings) > 0

    captured = capsys.readouterr()
    assert "Severity counts:" in captured.out
    assert "Top findings (up to 5):" in captured.out
    assert '"metadata"' not in captured.out
    top_lines = [line for line in captured.out.splitlines() if re.match(r"^\d+\.\s", line)]
    assert len(top_lines) <= 5


def test_explicit_scan_subcommand_writes_equivalent_report(
    monkeypatch: object,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
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
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
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


def test_no_api_key_fallback_reports_required_vulnerability_classes(
    monkeypatch: object,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    out_path = tmp_path / "fallback-report.json"

    exit_code = cli_main([str(DEMO_REPO), "--out", str(out_path), "--no-progress"])

    assert exit_code == 0
    report = _read_report(out_path)
    vuln_types = {finding.vuln_type for finding in report.findings}

    assert any(vuln_type.startswith("SECRET.") for vuln_type in vuln_types)
    assert any(vuln_type.startswith("SQLI.") for vuln_type in vuln_types)
    assert "AUTH.MISSING_ADMIN_GUARD" in vuln_types
    assert "CODE_EXEC.DYNAMIC_EVAL" in vuln_types
    assert "DESERIALIZE.UNSAFE_LOAD" in vuln_types
