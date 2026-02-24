id: csrf
title: Cross-Site Request Forgery (CWE-352)
domain: authz_access_control
weakness_type: csrf
cwe: CWE-352
owasp_2021: A01:Broken Access Control
exploit_classes: auth_bypass,integrity_violation
languages: python,node,java,php,ruby,go
tags: csrf,cwe-352,owasp-a01,session,web
severity_guidance: medium
---
CSRF tricks authenticated users into submitting unintended requests from a foreign origin.
State-changing endpoints that rely solely on cookies for authentication are vulnerable when CSRF tokens are absent.

Common indicators:
- state-changing POST/PUT/DELETE routes with no CSRF token validation
- SameSite cookie attribute not set to Strict or Lax
- reliance on cookie auth alone with no double-submit or synchronizer token

Impact:
- unauthorized account actions on behalf of victims
- fund transfers, email changes, password resets
- full account takeover in chained exploits

Recommended remediation:
- enforce synchronizer token pattern or double-submit cookie
- set SameSite=Strict or Lax on session cookies
- verify Origin/Referer headers as a secondary check
