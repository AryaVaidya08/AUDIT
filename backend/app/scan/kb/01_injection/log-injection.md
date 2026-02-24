id: log-injection
title: Log Injection / Log Forging (CWE-117)
domain: injection
weakness_type: log_injection
cwe: CWE-117
owasp_2021: A09:Security Logging and Monitoring Failures
exploit_classes: audit_trail_forgery
languages: python,node,java,go,php,ruby
tags: cwe-117,log-injection,log-forging,owasp-a09,logging
severity_guidance: medium
---
Log injection occurs when unsanitized user input is written directly to log files.
Attackers can forge log entries, obscure malicious activity, or exploit log viewers that parse log content as markup or commands.

Common indicators:
- logger.info(f"User logged in: {username}") with no newline stripping
- user-controlled values written verbatim to structured or plain-text logs
- log viewers (ELK, Splunk) that render HTML or execute links from log content

Impact:
- forged audit trail entries to cover attacker actions
- log viewer XSS or injection attacks
- confusion of SIEM alerts and incident response

Recommended remediation:
- sanitize log inputs by escaping or stripping newlines (\n, \r) and control characters
- use structured logging (JSON) with field-level encoding
- treat log data as untrusted in any downstream log processing system
