id: template-injection
title: Server-Side Template Injection (CWE-94)
domain: injection
weakness_type: template_injection
cwe: CWE-94
owasp_2021: A03:Injection
exploit_classes: rce
languages: python,java,node,php,ruby
tags: cwe-94,ssti,template-injection,rce,owasp-a03
severity_guidance: critical
---
SSTI occurs when user-supplied input is embedded directly into a server-side template and evaluated by the template engine.
Exploitation varies by engine (Jinja2, Twig, Freemarker, Pebble) but commonly leads to RCE.

Common indicators:
- template.render(user_input) or equivalent where input is the template string itself
- f-string-like interpolation with Jinja2/Twig syntax from request data
- error messages revealing template engine names and stack traces with template syntax

Impact:
- remote code execution on the server
- full environment variable and file system access
- lateral movement within internal infrastructure

Recommended remediation:
- never pass user input as the template source; only pass it as data context
- use sandboxed template rendering where available
- enforce strict allowlists for any dynamic template generation
