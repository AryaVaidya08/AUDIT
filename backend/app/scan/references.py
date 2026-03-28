from __future__ import annotations

from collections.abc import Collection, Iterable
from dataclasses import dataclass
import re
from typing import Literal

ReferenceKind = Literal["cwe", "owasp", "kb_doc", "unknown"]

_CWE_REFERENCE_PATTERN = re.compile(r"(?i)\bcwe(?:[-:\s]+)?(\d{1,5})\b")
_OWASP_REFERENCE_PATTERN = re.compile(r"(?i)\b(?:owasp[\s:_-]*)?a0?(\d{1,2})(?=\b|[:\s-])")


@dataclass(frozen=True, slots=True)
class ParsedReference:
    kind: ReferenceKind
    raw_value: str
    normalized_key: str
    numeric_id: int | None = None
    kb_doc_id: str = ""

    @property
    def canonical_value(self) -> str:
        if self.kind == "cwe" and self.numeric_id is not None:
            return f"CWE-{self.numeric_id}"
        if self.kind == "owasp" and self.numeric_id is not None:
            return f"OWASP-A{self.numeric_id:02d}"
        if self.kind == "kb_doc":
            return self.kb_doc_id
        return self.raw_value


def parse_reference(raw_value: str, *, kb_doc_ids: Collection[str] | None = None) -> ParsedReference:
    text = str(raw_value).strip()
    if not text:
        return ParsedReference(kind="unknown", raw_value="", normalized_key="")

    if kb_doc_ids is not None:
        kb_doc_id_lookup = {doc_id.lower(): doc_id for doc_id in kb_doc_ids}
        matched_doc_id = kb_doc_id_lookup.get(text.lower())
        if matched_doc_id is not None:
            return ParsedReference(
                kind="kb_doc",
                raw_value=text,
                normalized_key=matched_doc_id,
                kb_doc_id=matched_doc_id,
            )

    cwe_match = _CWE_REFERENCE_PATTERN.search(text)
    if cwe_match:
        cwe_id = int(cwe_match.group(1))
        return ParsedReference(
            kind="cwe",
            raw_value=text,
            normalized_key=f"cwe-{cwe_id}",
            numeric_id=cwe_id,
        )

    owasp_match = _OWASP_REFERENCE_PATTERN.search(text)
    if owasp_match:
        category = int(owasp_match.group(1))
        if 1 <= category <= 10:
            return ParsedReference(
                kind="owasp",
                raw_value=text,
                normalized_key=f"owasp-a{category:02d}",
                numeric_id=category,
            )

    return ParsedReference(kind="unknown", raw_value=text, normalized_key=text.lower())


def parse_references(
    raw_values: Iterable[str],
    *,
    kb_doc_ids: Collection[str] | None = None,
) -> list[ParsedReference]:
    return [parse_reference(raw_value, kb_doc_ids=kb_doc_ids) for raw_value in raw_values]


def canonicalize_standard_references(raw_values: Iterable[str]) -> list[str]:
    cwe_ids: set[int] = set()
    owasp_ids: set[int] = set()
    for parsed in parse_references(raw_values):
        if parsed.kind == "cwe" and parsed.numeric_id is not None:
            cwe_ids.add(parsed.numeric_id)
        elif parsed.kind == "owasp" and parsed.numeric_id is not None:
            owasp_ids.add(parsed.numeric_id)

    return [f"CWE-{cwe_id}" for cwe_id in sorted(cwe_ids)] + [
        f"OWASP-A{category:02d}" for category in sorted(owasp_ids)
    ]
