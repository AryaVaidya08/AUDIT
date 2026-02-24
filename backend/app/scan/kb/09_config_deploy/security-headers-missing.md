id: security-headers-missing
title: Missing HTTP Security Headers
domain: config_deploy
weakness_type: missing_security_headers
cwe: CWE-16
owasp_2021: A05:Security Misconfiguration
exploit_classes: session_hijack,data_exfil
languages: python,node,java,go,php,ruby
tags: cwe-16,security-headers,csp,hsts,owasp-a05,misconfiguration
severity_guidance: medium
---
Missing HTTP security response headers remove important browser-level defenses, leaving users vulnerable to clickjacking, XSS, downgrade attacks, and data leakage.
These headers are cheap to add and represent baseline security hygiene.

Common indicators:
- Strict-Transport-Security (HSTS) absent on HTTPS responses
- Content-Security-Policy header missing or set to unsafe-inline / unsafe-eval
- X-Content-Type-Options: nosniff not set (MIME sniffing attacks)
- Referrer-Policy absent, leaking sensitive URLs to third parties
- Permissions-Policy not configured, allowing full sensor/feature access

Impact:
- HTTPS downgrade attacks when HSTS is absent
- XSS impact amplified without CSP restrictions
- MIME confusion attacks exploiting missing nosniff directive
- sensitive URL leakage to analytics or ad networks via Referer headers

Recommended remediation:
- add Strict-Transport-Security with a long max-age and includeSubDomains
- set Content-Security-Policy with a restrictive policy; avoid unsafe-inline
- set X-Content-Type-Options: nosniff and Referrer-Policy: strict-origin-when-cross-origin
- use helmet (Node), SecurityMiddleware (Django), or equivalent framework defaults
