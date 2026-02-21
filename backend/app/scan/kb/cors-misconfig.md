id: cors-misconfig
title: CORS Misconfiguration
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
