id: information-disclosure
title: Information Disclosure via Error Messages (CWE-209)
domain: config_deploy
weakness_type: verbose_error_disclosure
cwe: CWE-209
owasp_2021: A05:Security Misconfiguration
exploit_classes: reconnaissance
languages: python,node,java,go,php,ruby
tags: cwe-209,information-disclosure,owasp-a05,error-handling,debug
severity_guidance: medium
---
Verbose error messages expose stack traces, framework versions, internal paths, SQL queries, or configuration details to end users.
This information materially aids attackers in fingerprinting and targeting the application.

Common indicators:
- unhandled exceptions returning full stack traces in HTTP responses
- DEBUG mode enabled in production (Django DEBUG=True, Flask debug=True)
- SQL error messages including query fragments returned in API responses
- version banners in Server, X-Powered-By, or X-AspNet-Version headers

Impact:
- technology fingerprinting enabling targeted exploitation
- internal path and architecture disclosure
- credential or configuration fragment leakage in error output

Recommended remediation:
- disable debug mode and verbose error output in production
- return generic error messages to clients; log details server-side only
- strip identifying headers (Server, X-Powered-By) from responses
