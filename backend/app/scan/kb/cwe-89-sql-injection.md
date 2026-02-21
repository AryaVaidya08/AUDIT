id: cwe-89-sql-injection
title: SQL Injection (OWASP Injection, CWE-89)
tags: cwe-89,owasp-a03,sqli,injection
severity_guidance: high
---
SQL injection occurs when untrusted input is concatenated into SQL queries.
This is CWE-89 and is covered by OWASP Injection guidance.

Common risky patterns:
- f-strings or string concatenation for SQL construction
- query text built with format() using request/user input
- execute/query calls with dynamic SQL and no parameterization

Impact:
- data exfiltration
- authentication bypass
- data corruption or destructive operations

Recommended remediation:
- always use parameterized queries/prepared statements
- avoid string-building SQL with user input
- apply least-privilege DB credentials
