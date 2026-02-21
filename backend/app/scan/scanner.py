from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal, Pattern

from app.scan.schema import CodeChunk, Finding, ScanReport


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
)


def _build_finding(rule: HeuristicRule, chunk: CodeChunk, line_number: int, line: str) -> Finding:
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        file_path=chunk.file_path,
        start_line=line_number,
        end_line=line_number,
        snippet=line.strip()[:300],
        description=rule.description,
    )


def scan_chunks(chunks: list[CodeChunk]) -> ScanReport:
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

    file_count = len({chunk.file_path for chunk in chunks})
    return ScanReport(findings=findings, files_scanned=file_count, chunks_scanned=len(chunks))
