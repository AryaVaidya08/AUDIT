id: ldap-injection
title: LDAP Injection (CWE-90)
domain: injection
weakness_type: ldap_injection
cwe: CWE-90
owasp_2021: A03:Injection
exploit_classes: auth_bypass,data_exfil
languages: java,python,php,node
tags: cwe-90,ldap-injection,injection,owasp-a03,auth
severity_guidance: high
---
LDAP injection occurs when user-supplied data is embedded in LDAP query filters without proper escaping.
Attackers can manipulate filter logic to bypass authentication or enumerate directory entries.

Common indicators:
- LDAP filters built with string concatenation: (&(uid=USER)(pass=PASS))
- user input not escaped for LDAP special characters: *, (, ), \, NUL
- bind or search operations using raw user credentials without sanitization

Impact:
- authentication bypass using always-true filter injection (*)(uid=*))(|(uid=*
- directory enumeration of users, groups, and attributes
- privilege escalation by injecting group membership conditions

Recommended remediation:
- escape all user input for LDAP filter special characters per RFC 4515
- use LDAP libraries with parameterized filter construction
- apply least-privilege service accounts for directory queries
