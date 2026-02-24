from __future__ import annotations

import json
from textwrap import dedent

from app.scan.schema import CodeChunk, RetrievalHit

PROMPT_VERSION = "v1"

_REQUIRED_FIELDS = (
    "vuln_type",
    "severity",
    "confidence",
    "references",
    "file_path",
    "start_line",
    "end_line",
    "message",
    "evidence",
    "recommendation",
)


def _render_hits(hits: list[RetrievalHit]) -> str:
    if not hits:
        return "[]"
    payload = [
        {k: v for k, v in {
            "id": hit.id,
            "title": hit.title,
            "score": round(hit.score, 4),
            "severity_guidance": hit.severity_guidance,
            "domain": hit.domain or None,
            "cwe": hit.cwe or None,
            "owasp_2021": hit.owasp_2021 or None,
            "tags": hit.tags,
            "preview": hit.preview,
        }.items() if v is not None}
        for hit in hits
    ]
    return json.dumps(payload, ensure_ascii=True, indent=2)


def build_audit_messages(chunk: CodeChunk, kb_hits: list[RetrievalHit]) -> tuple[str, str]:
    system_prompt = dedent(
        f"""
        You are a security auditor. Return JSON only.
        Output must be a JSON array.
        Every item must contain exactly these fields:
        {", ".join(_REQUIRED_FIELDS)}
        severity must be one of: low, medium, high, critical
        confidence must be a number between 0 and 1
        message must be a single-line summary.
        references must be a JSON array of short strings.
        If no security issue exists in this chunk, return [].
        """
    ).strip()

    user_prompt = dedent(
        f"""
        File: {chunk.file_path}
        Start line: {chunk.start_line}
        End line: {chunk.end_line}

        Security KB hits:
        {_render_hits(kb_hits)}

        Code chunk:
        ```text
        {chunk.text}
        ```
        """
    ).strip()
    return system_prompt, user_prompt


def build_repair_messages(raw_output: str) -> tuple[str, str]:
    system_prompt = dedent(
        """
        Fix the provided model output into valid JSON only.
        Return only a JSON array. No markdown, no commentary.
        """
    ).strip()

    user_prompt = dedent(
        f"""
        The previous output was invalid JSON for the required findings array.
        Rewrite it as valid JSON array only.

        Invalid output:
        {raw_output}
        """
    ).strip()
    return system_prompt, user_prompt
