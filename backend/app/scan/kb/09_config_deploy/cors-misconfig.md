id: cors-misconfig
title: CORS Misconfiguration
domain: config_deploy
weakness_type: cors_misconfiguration
cwe: CWE-942
owasp_2021: A05:Security Misconfiguration
exploit_classes: data_exfil,session_hijack
languages: python,node,java,go,php,ruby
tags: cors,owasp-a05,misconfiguration,web
severity_guidance: medium
---
CORS misconfigurations can expose APIs to cross-origin abuse when browsers are allowed to send privileged requests.
Risks increase when wildcard origins are combined with credentials.

Common indicators:
- Access-Control-Allow-Origin set to *
- allow_credentials enabled with broad origin matching
- dynamic origin reflection without validation

Impact:
- cross-origin data theft in browser contexts
- elevated risk of CSRF-like abuse patterns
- exposure of sensitive API responses

Recommended remediation:
- explicit origin allowlist
- never combine wildcard origin with credentials
- review all preflight and response CORS headers
