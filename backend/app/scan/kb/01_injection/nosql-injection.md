id: nosql-injection
title: NoSQL Injection (CWE-943)
domain: injection
weakness_type: nosql_injection
cwe: CWE-943
owasp_2021: A03:Injection
exploit_classes: data_exfil,auth_bypass
languages: node,python,java,go
tags: nosql-injection,injection,owasp-a03,mongodb,cwe-943
severity_guidance: high
---
NoSQL injection exploits dynamic query construction in document stores (MongoDB, CouchDB, DynamoDB).
Attackers inject query operators to bypass authentication or exfiltrate documents.

Common indicators:
- MongoDB queries built with user-supplied dicts: {"username": user_input}
- unvalidated JSON body passed as filter object
- use of $where, $regex, or $gt operators with untrusted values

Impact:
- authentication bypass (e.g., injecting {$ne: null})
- full collection data exfiltration
- query manipulation to return arbitrary documents

Recommended remediation:
- validate and sanitize query inputs; reject operator keys from user data
- use ODM type validation (Mongoose schema enforcement, etc.)
- apply principle of least-privilege database roles
