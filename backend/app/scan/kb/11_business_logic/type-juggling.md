id: type-juggling
title: Type Juggling / Loose Comparison Vulnerabilities (CWE-843)
domain: business_logic
weakness_type: type_confusion
cwe: CWE-843
owasp_2021: A04:Insecure Design
exploit_classes: auth_bypass,privesc
languages: php,javascript,python
tags: cwe-843,type-juggling,php,javascript,loose-comparison,auth
severity_guidance: high
---
Type juggling vulnerabilities arise when language type coercion is exploited during comparisons.
In PHP, loose comparison (==) between strings and numbers, or 0e-prefixed hashes, can bypass authentication.
In JavaScript, == coerces types in unexpected ways.

Common indicators:
- PHP: password hash comparisons using == instead of ===
- PHP: 0e followed by digits treated as 0 in scientific notation comparison
- JavaScript: == used for type-sensitive checks (null, undefined, 0, "")
- JSON input compared with type-coercing equality to enforce access control

Impact:
- authentication bypass with inputs like 0 or "0e..." matching arbitrary hashes
- authorization bypass where role checks use loose equality
- logic errors leading to privilege escalation

Recommended remediation:
- always use strict equality operators (=== in PHP and JavaScript)
- use constant-time comparison for secrets (hash_equals in PHP)
- never use == for security-sensitive comparisons involving mixed types
