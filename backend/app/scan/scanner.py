from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal, Pattern

from app.scan.schema import CodeChunk, Finding, ScanMetadata, ScanReport, ScanStats


@dataclass(frozen=True)
class HeuristicRule:
    rule_id: str
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    description: str
    pattern: Pattern[str]


RULES: tuple[HeuristicRule, ...] = (
    HeuristicRule(
        rule_id="SECRET.HARDCODED_ASSIGNMENT",
        title="Hardcoded secret assignment",
        severity="high",
        description="Potential hardcoded credential was found in code.",
        pattern=re.compile(
            r"""(?ix)
            \b(api[_-]?key|secret|token|password|passwd|pwd)\b
            \s*[:=]\s*
            ["'][^"'\n]{8,}["']
            """
        ),
    ),
    HeuristicRule(
        rule_id="SECRET.AWS_ACCESS_KEY",
        title="Hardcoded AWS access key",
        severity="high",
        description="Potential AWS access key embedded in source code.",
        pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    HeuristicRule(
        rule_id="SECRET.PRIVATE_KEY_MATERIAL",
        title="Private key material in source",
        severity="critical",
        description="Private key content appears to be committed in source code.",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ),
    HeuristicRule(
        rule_id="SQLI.DYNAMIC_QUERY",
        title="Potential SQL injection via dynamic query",
        severity="high",
        description="SQL statement looks dynamically composed from variables.",
        pattern=re.compile(r"(?i)\b(select|insert|update|delete)\b.{0,140}(\+|%s|format\(|\{|\$\{)"),
    ),
    HeuristicRule(
        rule_id="SQLI.EXECUTE_WITH_FSTRING",
        title="Potential SQL injection in execute/query call",
        severity="high",
        description="execute/query call appears to use a formatted SQL string.",
        pattern=re.compile(
            r"""(?ix)
            \b(execute|query)\s*\(
            \s*(f["']|["'][^"']{0,250}["']\s*\+)
            """
        ),
    ),
    HeuristicRule(
        rule_id="CODE_EXEC.DYNAMIC_EVAL",
        title="Dynamic code execution with eval/exec",
        severity="high",
        description="Direct eval/exec usage can execute attacker-controlled input.",
        pattern=re.compile(r"(?i)\b(eval|exec)\s*\("),
    ),
    HeuristicRule(
        rule_id="DESERIALIZE.UNSAFE_LOAD",
        title="Unsafe deserialization call",
        severity="high",
        description="Unsafe deserialization can enable arbitrary code execution.",
        pattern=re.compile(
            r"""(?ix)
            (
                \bpickle\.loads\s*\(
                |
                \byaml\.load\s*\(
                |
                \bmarshal\.loads\s*\(
                |
                \bdill\.loads\s*\(
                |
                \bunserialize\s*\(
            )
            """
        ),
    ),
)

_ADMIN_ROUTE_PATTERN = re.compile(
    r"""(?ix)
    \b(app|router|bp)\.(get|post|put|patch|delete|route)\s*\(
    \s*["']/(
        admin
        |internal
        |privileged
        |manage
        |root
    )[^"']*["']
    """
)
_AUTH_GUARD_PATTERN = re.compile(
    r"(?i)\b(auth|authorize|authorization|jwt|verify|require_?auth|is_admin|admin_required|login_required)\b"
)
_ADMIN_ROUTE_WINDOW_LINES = 10


def _build_finding(rule: HeuristicRule, chunk: CodeChunk, line_number: int, line: str) -> Finding:
    return Finding(
        vuln_type=rule.rule_id,
        severity=rule.severity,
        confidence=0.6,
        references=[],
        file_path=chunk.file_path,
        start_line=line_number,
        end_line=line_number,
        message=rule.title,
        evidence=line.strip()[:300],
        recommendation=rule.description,
    )


def _build_missing_auth_finding(chunk: CodeChunk, line_number: int, line: str) -> Finding:
    return Finding(
        vuln_type="AUTH.MISSING_ADMIN_GUARD",
        severity="high",
        confidence=0.55,
        references=[],
        file_path=chunk.file_path,
        start_line=line_number,
        end_line=line_number,
        message="Privileged route may be missing an auth check",
        evidence=line.strip()[:300],
        recommendation="Add authentication/authorization middleware or an explicit guard for privileged routes.",
    )


def _scan_missing_auth(chunk: CodeChunk, lines: list[str], seen: set[tuple[str, str, int]]) -> list[Finding]:
    findings: list[Finding] = []
    for offset, line in enumerate(lines):
        if not _ADMIN_ROUTE_PATTERN.search(line):
            continue

        line_number = chunk.start_line + offset
        window_text = "\n".join(lines[offset : offset + _ADMIN_ROUTE_WINDOW_LINES])
        if _AUTH_GUARD_PATTERN.search(window_text):
            continue

        dedup_key = ("AUTH.MISSING_ADMIN_GUARD", chunk.file_path, line_number)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        findings.append(_build_missing_auth_finding(chunk=chunk, line_number=line_number, line=line))
    return findings


def scan_chunks(chunks: list[CodeChunk]) -> ScanReport:
    started = datetime.now(timezone.utc)
    findings: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()

    for chunk in chunks:
        lines = chunk.text.splitlines()
        for offset, line in enumerate(lines):
            absolute_line = chunk.start_line + offset
            for rule in RULES:
                if not rule.pattern.search(line):
                    continue
                dedup_key = (rule.rule_id, chunk.file_path, absolute_line)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(_build_finding(rule=rule, chunk=chunk, line_number=absolute_line, line=line))
        findings.extend(_scan_missing_auth(chunk=chunk, lines=lines, seen=seen))

    file_count = len({chunk.file_path for chunk in chunks})
    finished = datetime.now(timezone.utc)
    return ScanReport(
        metadata=ScanMetadata(
            repo_path="(heuristic-scan)",
            scan_started_at=started,
            scan_finished_at=finished,
            model="heuristic-ruleset",
            top_k=1,
            similarity_threshold=0.0,
            max_chunks=len(chunks),
            chunk_size_lines=120,
            repair_retries=0,
        ),
        stats=ScanStats(
            files_scanned=file_count,
            chunks_considered=len(chunks),
            findings_before_dedup=len(findings),
            findings_after_dedup=len(findings),
        ),
        findings=findings,
    )
