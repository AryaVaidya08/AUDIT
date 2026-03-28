from __future__ import annotations

from app.scan.schema import RetrievalHit
from app.scan.taxonomy import resolve_finding_taxonomy


def test_resolve_finding_taxonomy_maps_current_heuristic_rule_ids() -> None:
    cases = [
        ("AUTH.MISSING_ADMIN_GUARD", "missing_auth_check", "Missing Authentication Check"),
        ("SECRET.HARDCODED_ASSIGNMENT", "hardcoded_credentials", "Hardcoded Credentials"),
        ("SECRET.AWS_ACCESS_KEY", "hardcoded_credentials", "Hardcoded Credentials"),
        ("SECRET.PRIVATE_KEY_MATERIAL", "exposed_private_key_material", "Exposed Private Key Material"),
        ("SQLI.DYNAMIC_QUERY", "sql_injection", "SQL Injection"),
        ("SQLI.EXECUTE_WITH_FSTRING", "sql_injection", "SQL Injection"),
        ("CODE_EXEC.DYNAMIC_EVAL", "unsafe_dynamic_code_execution", "Unsafe Dynamic Code Execution"),
        ("DESERIALIZE.UNSAFE_LOAD", "unsafe_native_deserialization", "Unsafe Native Deserialization"),
    ]

    for rule_id, expected_vuln_type, expected_title in cases:
        resolved = resolve_finding_taxonomy(rule_id=rule_id)
        assert resolved.vuln_type == expected_vuln_type
        assert resolved.title == expected_title
        assert resolved.rule_id == rule_id


def test_resolve_finding_taxonomy_maps_current_mixed_llm_labels() -> None:
    cases = [
        ("Missing Authentication and Authorization", "missing_auth_check", "Missing Authentication Check"),
        ("Hardcoded secret", "hardcoded_credentials", "Hardcoded Credentials"),
        ("Hardcoded Credentials", "hardcoded_credentials", "Hardcoded Credentials"),
        ("SQLI", "sql_injection", "SQL Injection"),
        ("Expression Language Injection", "unsafe_dynamic_code_execution", "Unsafe Dynamic Code Execution"),
        ("Code Injection via eval()", "unsafe_dynamic_code_execution", "Unsafe Dynamic Code Execution"),
        ("Unsafe Deserialization", "unsafe_native_deserialization", "Unsafe Native Deserialization"),
    ]

    for raw_label, expected_vuln_type, expected_title in cases:
        resolved = resolve_finding_taxonomy(vuln_type=raw_label)
        assert resolved.vuln_type == expected_vuln_type
        assert resolved.title == expected_title


def test_resolve_finding_taxonomy_prefers_eval_exec_special_case_over_expression_language_kb_type() -> None:
    resolved = resolve_finding_taxonomy(
        vuln_type="Expression Language Injection",
        message="User-controlled input reaches eval().",
        evidence="return eval(user_expression)",
        kb_hits=[
            RetrievalHit(
                id="expression-language-injection",
                title="Expression Language Injection (CWE-917)",
                score=0.95,
                severity_guidance="critical",
                weakness_type="expression_language_injection",
                tags=["cwe-917"],
                preview="Expression language injection can lead to remote code execution.",
            )
        ],
    )

    assert resolved.vuln_type == "unsafe_dynamic_code_execution"
    assert resolved.title == "Unsafe Dynamic Code Execution"


def test_resolve_finding_taxonomy_prefers_new_function_special_case_over_expression_language_kb_type() -> None:
    resolved = resolve_finding_taxonomy(
        vuln_type="Expression Language Injection",
        message="User-controlled input reaches new Function().",
        evidence="return new Function(userInput)()",
        kb_hits=[
            RetrievalHit(
                id="expression-language-injection",
                title="Expression Language Injection (CWE-917)",
                score=0.95,
                severity_guidance="critical",
                weakness_type="expression_language_injection",
                tags=["cwe-917"],
                preview="Expression language injection can lead to remote code execution.",
            )
        ],
    )

    assert resolved.vuln_type == "unsafe_dynamic_code_execution"
    assert resolved.title == "Unsafe Dynamic Code Execution"


def test_resolve_finding_taxonomy_prefers_deserialization_sink_over_broad_dynamic_code_label() -> None:
    resolved = resolve_finding_taxonomy(
        vuln_type="Unsafe Dynamic Code Execution",
        rule_id="cwe-94",
        references=["CWE-94"],
        message="Untrusted data is deserialized using pickle.loads().",
        evidence="return pickle.loads(raw_blob)",
    )

    assert resolved.vuln_type == "unsafe_native_deserialization"
    assert resolved.title == "Unsafe Native Deserialization"
    assert resolved.rule_id == "DESERIALIZE.UNSAFE_LOAD"


def test_resolve_finding_taxonomy_slugs_unknown_labels() -> None:
    resolved = resolve_finding_taxonomy(vuln_type="Weird Parser Bug")

    assert resolved.vuln_type == "weird_parser_bug"
    assert resolved.title == "Weird Parser Bug"
