from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping, Sequence

from app.scan.references import parse_references
from app.scan.schema import Finding, RetrievalHit

_DYNAMIC_CODE_EXECUTION_SINK_PATTERN = re.compile(r"(?ix)\b(?:eval|exec)\s*\(|\bnew\s+Function\s*\(")
_UNSAFE_DESERIALIZATION_SINK_PATTERN = re.compile(
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
)
_PARENS_PATTERN = re.compile(r"\s*\([^)]*\)")
_WHITESPACE_PATTERN = re.compile(r"\s+")
_SLUG_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")
_ACRONYM_TOKENS = {
    "api": "API",
    "cors": "CORS",
    "csrf": "CSRF",
    "graphql": "GraphQL",
    "http": "HTTP",
    "idor": "IDOR",
    "jwt": "JWT",
    "mfa": "MFA",
    "oauth": "OAuth",
    "os": "OS",
    "sql": "SQL",
    "sqli": "SQLi",
    "ssrf": "SSRF",
    "xss": "XSS",
    "xxe": "XXE",
    "xml": "XML",
}
_FINDING_FIELDS = {
    "vuln_type",
    "title",
    "rule_id",
    "severity",
    "confidence",
    "references",
    "file_path",
    "start_line",
    "end_line",
    "message",
    "evidence",
    "code_content",
    "kb_evidence",
    "recommendation",
}


@dataclass(frozen=True)
class TaxonomyResolution:
    vuln_type: str
    title: str
    rule_id: str | None = None


@dataclass(frozen=True)
class _AliasResolution:
    vuln_type: str
    title: str
    inferred_rule_id: str | None = None


_CANONICAL_TITLES: dict[str, str] = {
    "missing_auth_check": "Missing Authentication Check",
    "hardcoded_credentials": "Hardcoded Credentials",
    "exposed_private_key_material": "Exposed Private Key Material",
    "sql_injection": "SQL Injection",
    "unsafe_dynamic_code_execution": "Unsafe Dynamic Code Execution",
    "unsafe_native_deserialization": "Unsafe Native Deserialization",
}
_ALIASES: dict[str, _AliasResolution] = {
    "missing_auth_check": _AliasResolution("missing_auth_check", "Missing Authentication Check"),
    "auth.missing_admin_guard": _AliasResolution(
        "missing_auth_check",
        "Missing Authentication Check",
        inferred_rule_id="AUTH.MISSING_ADMIN_GUARD",
    ),
    "missing admin guard": _AliasResolution(
        "missing_auth_check",
        "Missing Authentication Check",
        inferred_rule_id="AUTH.MISSING_ADMIN_GUARD",
    ),
    "missing authentication and authorization": _AliasResolution(
        "missing_auth_check",
        "Missing Authentication Check",
    ),
    "missing authentication or authorization": _AliasResolution(
        "missing_auth_check",
        "Missing Authentication Check",
    ),
    "missing authentication or authorization middleware": _AliasResolution(
        "missing_auth_check",
        "Missing Authentication Check",
    ),
    "hardcoded_credentials": _AliasResolution("hardcoded_credentials", "Hardcoded Credentials"),
    "secret.hardcoded_assignment": _AliasResolution(
        "hardcoded_credentials",
        "Hardcoded Credentials",
        inferred_rule_id="SECRET.HARDCODED_ASSIGNMENT",
    ),
    "hardcoded secret": _AliasResolution("hardcoded_credentials", "Hardcoded Credentials"),
    "hardcoded secret assignment": _AliasResolution(
        "hardcoded_credentials",
        "Hardcoded Credentials",
        inferred_rule_id="SECRET.HARDCODED_ASSIGNMENT",
    ),
    "hardcoded credentials": _AliasResolution("hardcoded_credentials", "Hardcoded Credentials"),
    "use of hard-coded credentials": _AliasResolution("hardcoded_credentials", "Hardcoded Credentials"),
    "secret.aws_access_key": _AliasResolution(
        "hardcoded_credentials",
        "Hardcoded Credentials",
        inferred_rule_id="SECRET.AWS_ACCESS_KEY",
    ),
    "hardcoded aws access key": _AliasResolution(
        "hardcoded_credentials",
        "Hardcoded Credentials",
        inferred_rule_id="SECRET.AWS_ACCESS_KEY",
    ),
    "exposed_private_key_material": _AliasResolution(
        "exposed_private_key_material",
        "Exposed Private Key Material",
    ),
    "secret.private_key_material": _AliasResolution(
        "exposed_private_key_material",
        "Exposed Private Key Material",
        inferred_rule_id="SECRET.PRIVATE_KEY_MATERIAL",
    ),
    "private key material in source": _AliasResolution(
        "exposed_private_key_material",
        "Exposed Private Key Material",
        inferred_rule_id="SECRET.PRIVATE_KEY_MATERIAL",
    ),
    "sql_injection": _AliasResolution("sql_injection", "SQL Injection"),
    "sql injection": _AliasResolution("sql_injection", "SQL Injection"),
    "sqli": _AliasResolution("sql_injection", "SQL Injection"),
    "sqli.dynamic_query": _AliasResolution(
        "sql_injection",
        "SQL Injection",
        inferred_rule_id="SQLI.DYNAMIC_QUERY",
    ),
    "potential sql injection via dynamic query": _AliasResolution(
        "sql_injection",
        "SQL Injection",
        inferred_rule_id="SQLI.DYNAMIC_QUERY",
    ),
    "sqli.execute_with_fstring": _AliasResolution(
        "sql_injection",
        "SQL Injection",
        inferred_rule_id="SQLI.EXECUTE_WITH_FSTRING",
    ),
    "potential sql injection in execute/query call": _AliasResolution(
        "sql_injection",
        "SQL Injection",
        inferred_rule_id="SQLI.EXECUTE_WITH_FSTRING",
    ),
    "sql injection (owasp injection, cwe-89)": _AliasResolution("sql_injection", "SQL Injection"),
    "unsafe_dynamic_code_execution": _AliasResolution(
        "unsafe_dynamic_code_execution",
        "Unsafe Dynamic Code Execution",
    ),
    "expression_language_injection": _AliasResolution(
        "unsafe_dynamic_code_execution",
        "Unsafe Dynamic Code Execution",
    ),
    "expression language injection": _AliasResolution(
        "unsafe_dynamic_code_execution",
        "Unsafe Dynamic Code Execution",
    ),
    "expression language injection (cwe-917)": _AliasResolution(
        "unsafe_dynamic_code_execution",
        "Unsafe Dynamic Code Execution",
    ),
    "el injection": _AliasResolution("unsafe_dynamic_code_execution", "Unsafe Dynamic Code Execution"),
    "code injection via eval()": _AliasResolution(
        "unsafe_dynamic_code_execution",
        "Unsafe Dynamic Code Execution",
        inferred_rule_id="CODE_EXEC.DYNAMIC_EVAL",
    ),
    "code_exec.dynamic_eval": _AliasResolution(
        "unsafe_dynamic_code_execution",
        "Unsafe Dynamic Code Execution",
        inferred_rule_id="CODE_EXEC.DYNAMIC_EVAL",
    ),
    "dynamic code execution with eval/exec": _AliasResolution(
        "unsafe_dynamic_code_execution",
        "Unsafe Dynamic Code Execution",
        inferred_rule_id="CODE_EXEC.DYNAMIC_EVAL",
    ),
    "unsafe_native_deserialization": _AliasResolution(
        "unsafe_native_deserialization",
        "Unsafe Native Deserialization",
    ),
    "unsafe deserialization": _AliasResolution(
        "unsafe_native_deserialization",
        "Unsafe Native Deserialization",
    ),
    "unsafe native deserialization": _AliasResolution(
        "unsafe_native_deserialization",
        "Unsafe Native Deserialization",
    ),
    "unsafe native deserialization (cwe-502)": _AliasResolution(
        "unsafe_native_deserialization",
        "Unsafe Native Deserialization",
    ),
    "insecure_deserialization": _AliasResolution(
        "unsafe_native_deserialization",
        "Unsafe Native Deserialization",
    ),
    "deserialze.unsafe_load": _AliasResolution(
        "unsafe_native_deserialization",
        "Unsafe Native Deserialization",
        inferred_rule_id="DESERIALIZE.UNSAFE_LOAD",
    ),
    "deserialize.unsafe_load": _AliasResolution(
        "unsafe_native_deserialization",
        "Unsafe Native Deserialization",
        inferred_rule_id="DESERIALIZE.UNSAFE_LOAD",
    ),
    "unsafe deserialization call": _AliasResolution(
        "unsafe_native_deserialization",
        "Unsafe Native Deserialization",
        inferred_rule_id="DESERIALIZE.UNSAFE_LOAD",
    ),
}


def _clean_text(raw_value: Any) -> str:
    return str(raw_value or "").strip()


def _alias_lookup_keys(raw_value: str) -> list[str]:
    value = _clean_text(raw_value)
    if not value:
        return []
    lowered = value.lower()
    keys = [lowered]
    without_parens = _WHITESPACE_PATTERN.sub(" ", _PARENS_PATTERN.sub("", lowered)).strip()
    if without_parens and without_parens not in keys:
        keys.append(without_parens)
    return keys


def _slugify(raw_value: str) -> str:
    tokens = _SLUG_TOKEN_PATTERN.findall(_clean_text(raw_value).lower())
    return "_".join(tokens) if tokens else "unspecified"


def _fallback_title(*, vuln_type: str, raw_title: str, raw_label: str) -> str:
    cleaned_title = _clean_text(raw_title)
    if cleaned_title:
        return cleaned_title.splitlines()[0].strip()

    cleaned_label = _clean_text(raw_label)
    if cleaned_label and cleaned_label != vuln_type:
        return cleaned_label.splitlines()[0].strip()

    words: list[str] = []
    for token in vuln_type.split("_"):
        if token in _ACRONYM_TOKENS:
            words.append(_ACRONYM_TOKENS[token])
        elif token:
            words.append(token.capitalize())
    return " ".join(words) or "Unspecified"


def _resolve_alias(raw_value: str) -> _AliasResolution | None:
    for key in _alias_lookup_keys(raw_value):
        resolution = _ALIASES.get(key)
        if resolution is not None:
            return resolution
    return None


def _normalize_references(raw_value: Any) -> list[str]:
    if raw_value is None:
        return []
    if isinstance(raw_value, str):
        cleaned = raw_value.strip()
        return [cleaned] if cleaned else []
    if isinstance(raw_value, Sequence) and not isinstance(raw_value, (bytes, bytearray)):
        values: list[str] = []
        for item in raw_value:
            cleaned = _clean_text(item)
            if cleaned:
                values.append(cleaned)
        return values
    cleaned = _clean_text(raw_value)
    return [cleaned] if cleaned else []


def _coerce_kb_hits(raw_value: Any) -> list[RetrievalHit]:
    if not isinstance(raw_value, list):
        return []
    hits: list[RetrievalHit] = []
    for item in raw_value:
        try:
            hits.append(RetrievalHit.model_validate(item))
        except Exception:
            continue
    return hits


def contains_dynamic_code_execution_sink(*parts: Any) -> bool:
    combined_context = "\n".join(_clean_text(part) for part in parts if _clean_text(part))
    if not combined_context:
        return False
    return bool(_DYNAMIC_CODE_EXECUTION_SINK_PATTERN.search(combined_context))


def contains_unsafe_native_deserialization_sink(*parts: Any) -> bool:
    combined_context = "\n".join(_clean_text(part) for part in parts if _clean_text(part))
    if not combined_context:
        return False
    return bool(_UNSAFE_DESERIALIZATION_SINK_PATTERN.search(combined_context))


def _uses_dynamic_eval(
    *,
    raw_vuln_type: str,
    raw_title: str,
    raw_rule_id: str,
    references: Sequence[str],
    kb_hits: Sequence[RetrievalHit],
    message: str,
    evidence: str,
    code_content: str,
    context: str,
) -> bool:
    normalized_references = {
        reference.normalized_key
        for reference in parse_references(list(references))
        if reference.normalized_key
    }
    alias_candidates = {
        key
        for raw_value in (raw_vuln_type, raw_title, raw_rule_id)
        for key in _alias_lookup_keys(raw_value)
    }
    if "expression language injection" in alias_candidates or "expression_language_injection" in alias_candidates:
        pass
    elif "cwe-917" in normalized_references:
        pass
    elif any(hit.weakness_type.strip() == "expression_language_injection" for hit in kb_hits):
        pass
    else:
        return False

    return contains_dynamic_code_execution_sink(message, evidence, code_content, context)


def resolve_finding_taxonomy(
    *,
    vuln_type: str | None = None,
    title: str | None = None,
    rule_id: str | None = None,
    references: Sequence[str] | None = None,
    kb_hits: Sequence[RetrievalHit] | None = None,
    message: str | None = None,
    evidence: str | None = None,
    code_content: str | None = None,
    context: str | None = None,
) -> TaxonomyResolution:
    raw_vuln_type = _clean_text(vuln_type)
    raw_title = _clean_text(title)
    raw_rule_id = _clean_text(rule_id)
    normalized_references = _normalize_references(references)
    selected_kb_hits = list(kb_hits or [])

    kb_resolution: _AliasResolution | None = None
    for hit in selected_kb_hits:
        weakness_type = _clean_text(hit.weakness_type)
        if not weakness_type:
            continue
        kb_resolution = _resolve_alias(weakness_type) or _AliasResolution(
            vuln_type=_slugify(weakness_type),
            title=_CANONICAL_TITLES.get(_slugify(weakness_type), _fallback_title(
                vuln_type=_slugify(weakness_type),
                raw_title=hit.title,
                raw_label=weakness_type,
            )),
        )
        break

    alias_resolution = _resolve_alias(raw_rule_id) or _resolve_alias(raw_vuln_type) or _resolve_alias(raw_title)
    dynamic_eval = _uses_dynamic_eval(
        raw_vuln_type=raw_vuln_type,
        raw_title=raw_title,
        raw_rule_id=raw_rule_id,
        references=normalized_references,
        kb_hits=selected_kb_hits,
        message=_clean_text(message),
        evidence=_clean_text(evidence),
        code_content=_clean_text(code_content),
        context=_clean_text(context),
    )
    unsafe_deserialization = contains_unsafe_native_deserialization_sink(
        _clean_text(message),
        _clean_text(evidence),
    )

    chosen = kb_resolution or alias_resolution
    if chosen is None and unsafe_deserialization:
        chosen = _ALIASES["unsafe_native_deserialization"]
    if chosen is None and dynamic_eval:
        chosen = _ALIASES["unsafe_dynamic_code_execution"]

    if chosen is None:
        raw_label = raw_vuln_type or raw_title or raw_rule_id or "unspecified"
        fallback_vuln_type = _slugify(raw_label)
        return TaxonomyResolution(
            vuln_type=fallback_vuln_type,
            title=_CANONICAL_TITLES.get(
                fallback_vuln_type,
                _fallback_title(vuln_type=fallback_vuln_type, raw_title=raw_title, raw_label=raw_label),
            ),
            rule_id=raw_rule_id or None,
        )

    resolved_vuln_type = chosen.vuln_type
    resolved_title = chosen.title
    resolved_rule_id = raw_rule_id or chosen.inferred_rule_id

    if unsafe_deserialization:
        resolved_vuln_type = "unsafe_native_deserialization"
        resolved_title = _CANONICAL_TITLES[resolved_vuln_type]
        resolved_rule_id = "DESERIALIZE.UNSAFE_LOAD"

    if dynamic_eval and resolved_vuln_type == "expression_language_injection":
        resolved_vuln_type = "unsafe_dynamic_code_execution"
        resolved_title = _CANONICAL_TITLES[resolved_vuln_type]

    return TaxonomyResolution(
        vuln_type=resolved_vuln_type,
        title=resolved_title,
        rule_id=resolved_rule_id or None,
    )


def normalize_finding_payload(
    payload: Mapping[str, Any],
    *,
    kb_hits: Sequence[RetrievalHit] | None = None,
    context: str | None = None,
) -> dict[str, Any]:
    data = {key: payload[key] for key in _FINDING_FIELDS if key in payload}
    references = _normalize_references(data.get("references"))
    existing_kb_hits = _coerce_kb_hits(data.get("kb_evidence"))
    selected_kb_hits = list(kb_hits) if kb_hits is not None else existing_kb_hits

    resolution = resolve_finding_taxonomy(
        vuln_type=_clean_text(data.get("vuln_type")),
        title=_clean_text(data.get("title")),
        rule_id=_clean_text(data.get("rule_id")),
        references=references,
        kb_hits=selected_kb_hits or existing_kb_hits,
        message=_clean_text(data.get("message")),
        evidence=_clean_text(data.get("evidence")),
        code_content=_clean_text(data.get("code_content")),
        context=context,
    )

    data["vuln_type"] = resolution.vuln_type
    data["title"] = resolution.title
    if resolution.rule_id:
        data["rule_id"] = resolution.rule_id
    else:
        data.pop("rule_id", None)

    data["references"] = references
    data["kb_evidence"] = [hit.model_dump(mode="json") for hit in existing_kb_hits]

    message = _clean_text(data.get("message"))
    data["message"] = message.splitlines()[0].strip() if message else f"Potential issue: {resolution.title}"
    return data


def restore_finding(
    payload: Mapping[str, Any],
    *,
    kb_hits: Sequence[RetrievalHit] | None = None,
    context: str | None = None,
) -> Finding:
    return Finding.model_validate(normalize_finding_payload(payload, kb_hits=kb_hits, context=context))
