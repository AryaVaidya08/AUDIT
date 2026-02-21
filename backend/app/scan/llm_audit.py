from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover - optional runtime dependency
    OpenAI = None  # type: ignore[assignment]

from app.scan.prompts import build_audit_messages, build_repair_messages
from app.scan.schema import CodeChunk, Finding, RetrievalHit

_SEVERITY_MAP = {
    "low": "low",
    "info": "low",
    "informational": "low",
    "medium": "medium",
    "moderate": "medium",
    "high": "high",
    "important": "high",
    "critical": "critical",
    "severe": "critical",
}


@dataclass(frozen=True)
class ChunkAuditResult:
    findings: list[Finding]
    llm_calls: int = 0
    llm_retries: int = 0
    parse_failures: int = 0
    skipped_parse_error: bool = False
    error_reason: str | None = None


def _extract_response_text(response: Any) -> str:
    choices = getattr(response, "choices", None)
    if not choices:
        return ""
    message = getattr(choices[0], "message", None)
    if message is None:
        return ""
    content = getattr(message, "content", "")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        text_parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                raw_text = item.get("text")
                if isinstance(raw_text, str):
                    text_parts.append(raw_text)
            else:
                raw_text = getattr(item, "text", None)
                if isinstance(raw_text, str):
                    text_parts.append(raw_text)
        return "\n".join(part.strip() for part in text_parts if part.strip()).strip()
    return str(content).strip()


def _normalize_confidence(raw_value: Any) -> float:
    try:
        value = float(raw_value)
    except (TypeError, ValueError):
        value = 0.0
    return min(max(value, 0.0), 1.0)


def _normalize_severity(raw_value: Any) -> str:
    normalized = str(raw_value or "").strip().lower()
    if normalized in _SEVERITY_MAP:
        return _SEVERITY_MAP[normalized]
    return "medium"


def _normalize_line(raw_value: Any, fallback: int) -> int:
    try:
        line = int(raw_value)
    except (TypeError, ValueError):
        return fallback
    return max(1, line)


def _normalize_references(raw_value: Any) -> list[str]:
    if raw_value is None:
        return []
    if isinstance(raw_value, str):
        text = raw_value.strip()
        return [text] if text else []
    if isinstance(raw_value, list):
        output: list[str] = []
        for item in raw_value:
            text = str(item).strip()
            if text:
                output.append(text)
        return output
    text = str(raw_value).strip()
    return [text] if text else []


def _normalize_one_liner(raw_value: Any, fallback: str) -> str:
    text = str(raw_value or "").strip()
    if not text:
        return fallback
    return text.splitlines()[0].strip() or fallback


def _coerce_finding_payload(item: dict[str, Any], chunk: CodeChunk) -> dict[str, Any]:
    vuln_type = str(item.get("vuln_type") or item.get("rule_id") or item.get("title") or "unspecified").strip()
    if not vuln_type:
        vuln_type = "unspecified"
    start_line = _normalize_line(item.get("start_line"), chunk.start_line)
    end_line = _normalize_line(item.get("end_line"), start_line)
    if end_line < start_line:
        end_line = start_line
    message = _normalize_one_liner(item.get("message"), fallback=f"Potential issue: {vuln_type}")
    evidence = str(item.get("evidence") or item.get("snippet") or "No evidence supplied by model.").strip()
    recommendation = str(
        item.get("recommendation")
        or item.get("description")
        or "Review and apply secure coding guidance for this vulnerability type."
    ).strip()
    return {
        "vuln_type": vuln_type,
        "severity": _normalize_severity(item.get("severity")),
        "confidence": _normalize_confidence(item.get("confidence")),
        "references": _normalize_references(item.get("references")),
        "file_path": str(item.get("file_path") or chunk.file_path),
        "start_line": start_line,
        "end_line": end_line,
        "message": message,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def _parse_findings(raw_output: str, chunk: CodeChunk) -> list[Finding]:
    payload = json.loads(raw_output)
    if isinstance(payload, dict):
        nested = payload.get("findings")
        if isinstance(nested, list):
            payload = nested
        else:
            raise ValueError("Expected JSON array or object with findings[]")
    if not isinstance(payload, list):
        raise ValueError("Expected JSON array output")

    findings: list[Finding] = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise ValueError(f"Finding at index {index} is not an object")
        normalized = _coerce_finding_payload(item, chunk)
        findings.append(Finding.model_validate(normalized))
    return findings


def _build_openai_client(api_key: str | None = None) -> Any | None:
    resolved_key = api_key if api_key is not None else os.getenv("OPENAI_API_KEY")
    if OpenAI is None or not resolved_key:
        return None
    return OpenAI(api_key=resolved_key)


def _chat(client: Any, model: str, system_prompt: str, user_prompt: str) -> str:
    response = client.chat.completions.create(
        model=model,
        temperature=0,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    )
    return _extract_response_text(response)


def audit_chunk_with_llm(
    chunk: CodeChunk,
    kb_hits: list[RetrievalHit],
    model: str,
    repair_retries: int = 1,
    api_key: str | None = None,
    client: Any | None = None,
) -> ChunkAuditResult:
    llm_client = client if client is not None else _build_openai_client(api_key=api_key)
    if llm_client is None:
        return ChunkAuditResult(findings=[], error_reason="llm_unavailable")

    llm_calls = 0
    llm_retries = 0
    parse_failures = 0
    raw_output = ""
    last_error = "unknown_error"

    for attempt in range(max(0, repair_retries) + 1):
        if attempt == 0:
            system_prompt, user_prompt = build_audit_messages(chunk=chunk, kb_hits=kb_hits)
        else:
            llm_retries += 1
            system_prompt, user_prompt = build_repair_messages(raw_output=raw_output)

        try:
            raw_output = _chat(llm_client, model=model, system_prompt=system_prompt, user_prompt=user_prompt)
            llm_calls += 1
            findings = _parse_findings(raw_output=raw_output, chunk=chunk)
            return ChunkAuditResult(
                findings=findings,
                llm_calls=llm_calls,
                llm_retries=llm_retries,
                parse_failures=parse_failures,
            )
        except Exception as exc:
            parse_failures += 1
            last_error = str(exc)
            continue

    return ChunkAuditResult(
        findings=[],
        llm_calls=llm_calls,
        llm_retries=llm_retries,
        parse_failures=parse_failures,
        skipped_parse_error=True,
        error_reason=last_error,
    )
