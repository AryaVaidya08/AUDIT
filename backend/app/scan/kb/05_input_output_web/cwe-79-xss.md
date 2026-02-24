id: cwe-79-xss
title: Cross-Site Scripting (OWASP XSS, CWE-79)
domain: input_output_web
weakness_type: cross_site_scripting
cwe: CWE-79
owasp_2021: A03:Injection
exploit_classes: session_hijack,data_exfil
languages: javascript,typescript,python,php,java,ruby
tags: cwe-79,owasp-a03,xss,frontend
severity_guidance: medium
---
Cross-site scripting happens when untrusted content is rendered as executable HTML/JS.
This maps to CWE-79 and remains a core OWASP Injection class issue.

Common indicators:
- direct assignment to innerHTML with user-controlled input
- unsafe template rendering without auto-escaping
- reflected parameters rendered in responses without encoding

Impact:
- session theft
- account takeover
- malicious actions in victim browser context

Recommended remediation:
- context-aware output encoding
- framework auto-escaping defaults
- content security policy as defense-in-depth
