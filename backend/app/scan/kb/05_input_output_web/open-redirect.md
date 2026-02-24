id: open-redirect
title: Open Redirect (CWE-601)
domain: input_output_web
weakness_type: open_redirect
cwe: CWE-601
owasp_2021: A01:Broken Access Control
exploit_classes: phishing,token_theft
languages: python,node,java,go,php,ruby
tags: cwe-601,open-redirect,phishing,owasp-a01
severity_guidance: medium
---
Open redirects allow attackers to craft trusted-looking URLs that redirect victims to malicious destinations.
They are commonly found in login, logout, and OAuth callback flows.

Common indicators:
- redirect_to, next, return_url, or url parameters passed directly to HTTP Location headers
- client-side window.location assignment from query parameters
- OAuth state parameter used unsanitized as redirect target

Impact:
- phishing via trusted domain lure
- OAuth token theft through redirect_uri abuse
- chaining with XSS or SSRF for elevated impact

Recommended remediation:
- validate redirect targets against a strict allowlist of known internal paths
- reject absolute URLs or off-domain destinations
- encode and validate OAuth state and redirect_uri parameters server-side
