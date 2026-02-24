id: clickjacking
title: Clickjacking / UI Redressing (CWE-1021)
domain: config_deploy
weakness_type: clickjacking
cwe: CWE-1021
owasp_2021: A05:Security Misconfiguration
exploit_classes: integrity_violation,auth_bypass
languages: python,node,java,go,php,ruby
tags: cwe-1021,clickjacking,ui-redressing,owasp-a05,headers
severity_guidance: medium
---
Clickjacking embeds a target site in a transparent iframe, tricking users into performing unintended actions by clicking on invisible elements.
Sensitive actions like account deletion, fund transfer, or settings changes are common targets.

Common indicators:
- missing X-Frame-Options or Content-Security-Policy frame-ancestors headers
- application embeddable by any third-party origin
- sensitive state-changing UI without re-authentication or confirmation dialogs

Impact:
- unintended sensitive actions performed by victim users
- likejacking, forced follows, or social media manipulation
- account setting changes without user awareness

Recommended remediation:
- set X-Frame-Options: DENY or SAMEORIGIN
- use Content-Security-Policy: frame-ancestors 'none' or specific trusted origins
- add user interaction confirmation for high-impact actions
