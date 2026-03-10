from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

try:
    from openai import OpenAI
    from openai import RateLimitError as _RateLimitError
except ImportError:
    OpenAI = None
    _RateLimitError = None

from app.scan.prompts import build_audit_messages
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


class _StructuredFindingPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    vuln_type: str
    severity: str
    confidence: float | int | str | None
    references: list[str] | str | None
    file_path: str
    start_line: int | str
    end_line: int | str
    message: str
    evidence: str
    recommendation: str


class _StructuredFindingsEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    findings: list[_StructuredFindingPayload]


_AUDIT_RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "audit_findings",
        "strict": True,
        "schema": _StructuredFindingsEnvelope.model_json_schema(),
    },
}


@dataclass(frozen=True)
class ChunkAuditResult:
    findings: list[Finding]
    llm_calls: int = 0
    llm_retries: int = 0
    parse_failures: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    skipped_parse_error: bool = False
    error_reason: str | None = None


def llm_is_available(api_key: str | None = None) -> bool:
    resolved_key = api_key if api_key is not None else os.getenv("OPENAI_API_KEY")
    return OpenAI is not None and bool(resolved_key)


_validated_api_keys: set[str] = set()


def validate_api_key(api_key: str | None = None) -> str | None:
    """Validate the OpenAI API key format and connectivity.

    Returns ``None`` on success or a warning message string on failure.
    Only the missing-key / missing-package cases are fatal (raise
    ``RuntimeError``) because those are configuration errors that can
    never self-heal.  A transient network failure is returned as a
    warning so the caller can log it and let per-chunk error handling
    deal with the problem.
    """
    resolved_key = api_key if api_key is not None else os.getenv("OPENAI_API_KEY")
    if not resolved_key:
        raise RuntimeError("OPENAI_API_KEY is not set.")
    if resolved_key in _validated_api_keys:
        return None
    client = _build_openai_client(api_key=resolved_key)
    if client is None:
        raise RuntimeError("Failed to build OpenAI client. Is the openai package installed?")
    try:
        client.models.list(timeout=10.0)
    except Exception as exc:
        return f"OpenAI API key validation failed (will retry per-chunk): {exc}"
    _validated_api_keys.add(resolved_key)
    return None


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


def _extract_token_usage(response: Any) -> tuple[int, int, int]:
    usage = getattr(response, "usage", None)
    if usage is None:
        return 0, 0, 0

    if isinstance(usage, dict):
        prompt_tokens = int(usage.get("prompt_tokens", 0) or 0)
        completion_tokens = int(usage.get("completion_tokens", 0) or 0)
        total_tokens = int(usage.get("total_tokens", 0) or 0)
    else:
        prompt_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
        completion_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
        total_tokens = int(getattr(usage, "total_tokens", 0) or 0)
    if total_tokens <= 0:
        total_tokens = max(prompt_tokens + completion_tokens, 0)
    return max(prompt_tokens, 0), max(completion_tokens, 0), max(total_tokens, 0)


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


def _parse_positive_int(raw_value: Any, fallback: int) -> int:
    try:
        line = int(raw_value)
    except (TypeError, ValueError):
        return fallback
    return max(1, line)


def _normalize_line_in_chunk(raw_value: Any, *, chunk: CodeChunk, fallback: int) -> int:
    line = _parse_positive_int(raw_value, fallback=fallback)
    if chunk.start_line <= line <= chunk.end_line:
        return line

    chunk_length = max(1, chunk.end_line - chunk.start_line + 1)
    if 1 <= line <= chunk_length:
        return chunk.start_line + (line - 1)

    return min(max(line, chunk.start_line), chunk.end_line)


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
    start_line = _normalize_line_in_chunk(item.get("start_line"), chunk=chunk, fallback=chunk.start_line)
    end_line = _normalize_line_in_chunk(item.get("end_line"), chunk=chunk, fallback=start_line)
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
    payload = _StructuredFindingsEnvelope.model_validate_json(raw_output)
    findings: list[Finding] = []
    for item in payload.findings:
        normalized = _coerce_finding_payload(item.model_dump(mode="python"), chunk)
        findings.append(Finding.model_validate(normalized))
    return findings


def _build_openai_client(api_key: str | None = None) -> Any | None:
    resolved_key = api_key if api_key is not None else os.getenv("OPENAI_API_KEY")
    if not llm_is_available(resolved_key):
        return None
    return OpenAI(api_key=resolved_key)


def _normalize_timeout(timeout_seconds: float | None) -> float:
    if timeout_seconds is None:
        return 20.0
    try:
        normalized = float(timeout_seconds)
    except (TypeError, ValueError):
        return 20.0
    return max(1.0, normalized)


def _chat(
    client: Any,
    model: str,
    system_prompt: str,
    user_prompt: str,
    timeout_seconds: float,
) -> tuple[str, int, int, int]:
    response = client.chat.completions.create(
        model=model,
        temperature=0,
        timeout=timeout_seconds,
        response_format=_AUDIT_RESPONSE_FORMAT,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    )
    prompt_tokens, completion_tokens, total_tokens = _extract_token_usage(response)
    return _extract_response_text(response), prompt_tokens, completion_tokens, total_tokens


def audit_chunk_with_llm(
    chunk: CodeChunk,
    kb_hits: list[RetrievalHit],
    model: str,
    repair_retries: int = 1,
    timeout_seconds: float | None = None,
    api_key: str | None = None,
    client: Any | None = None,
) -> ChunkAuditResult:
    llm_client = client if client is not None else _build_openai_client(api_key=api_key)
    if llm_client is None:
        return ChunkAuditResult(findings=[], error_reason="llm_unavailable")

    llm_calls = 0
    llm_retries = 0
    parse_failures = 0
    prompt_tokens = 0
    completion_tokens = 0
    total_tokens = 0
    last_error = "unknown_error"
    effective_timeout = _normalize_timeout(timeout_seconds)
    system_prompt, user_prompt = build_audit_messages(chunk=chunk, kb_hits=kb_hits)

    for attempt in range(max(0, repair_retries) + 1):
        if attempt > 0:
            llm_retries += 1

        try:
            max_rate_limit_retries = 3
            for rate_limit_attempt in range(max_rate_limit_retries + 1):
                try:
                    raw_output, call_prompt_tokens, call_completion_tokens, call_total_tokens = _chat(
                        llm_client,
                        model=model,
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        timeout_seconds=effective_timeout,
                    )
                    break
                except Exception as rate_exc:
                    if (
                        _RateLimitError is not None
                        and isinstance(rate_exc, _RateLimitError)
                        and rate_limit_attempt < max_rate_limit_retries
                    ):
                        time.sleep(2 ** (rate_limit_attempt + 1))
                        continue
                    raise
            llm_calls += 1
            prompt_tokens += call_prompt_tokens
            completion_tokens += call_completion_tokens
            total_tokens += call_total_tokens
            findings = _parse_findings(raw_output=raw_output, chunk=chunk)
            return ChunkAuditResult(
                findings=findings,
                llm_calls=llm_calls,
                llm_retries=llm_retries,
                parse_failures=parse_failures,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
            )
        except (ValidationError, ValueError, KeyError) as exc:
            parse_failures += 1
            last_error = f"parse_error: {exc}"
        except Exception as exc:
            last_error = str(exc)
            continue

    return ChunkAuditResult(
        findings=[],
        llm_calls=llm_calls,
        llm_retries=llm_retries,
        parse_failures=parse_failures,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
        skipped_parse_error=True,
        error_reason=last_error,
    )
