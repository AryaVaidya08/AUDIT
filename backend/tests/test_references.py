from __future__ import annotations

from app.scan.references import canonicalize_standard_references, parse_reference


def test_parse_reference_prefers_exact_kb_doc_id_before_standard_parsing() -> None:
    parsed = parse_reference("cwe-89-sql-injection", kb_doc_ids={"cwe-89-sql-injection"})

    assert parsed.kind == "kb_doc"
    assert parsed.kb_doc_id == "cwe-89-sql-injection"


def test_parse_reference_normalizes_cwe_and_owasp_variants() -> None:
    cwe = parse_reference("CWE:89")
    owasp = parse_reference("OWASP A3")

    assert cwe.kind == "cwe"
    assert cwe.normalized_key == "cwe-89"
    assert cwe.canonical_value == "CWE-89"
    assert owasp.kind == "owasp"
    assert owasp.normalized_key == "owasp-a03"
    assert owasp.canonical_value == "OWASP-A03"


def test_canonicalize_standard_references_dedupes_and_orders_deterministically() -> None:
    references = canonicalize_standard_references(
        [
            "OWASP A3",
            "cwe-306",
            "CWE 89",
            "A01:Broken Access Control",
            "cwe-89",
            "expression-language-injection",
        ]
    )

    assert references == ["CWE-89", "CWE-306", "OWASP-A01", "OWASP-A03"]
