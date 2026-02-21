id: command-injection
title: Command Injection (CWE-78)
tags: cwe-78,command-injection,rce,owasp-a03
severity_guidance: critical
---
Command injection happens when untrusted input reaches shell execution APIs.
Typical sinks include os.system, subprocess with shell=True, and runtime eval/exec usage.

Common indicators:
- os.system(user_input)
- subprocess.run with shell=True and interpolated strings
- eval/exec on untrusted data

Impact:
- remote code execution
- full server compromise
- data destruction or exfiltration

Recommended remediation:
- avoid shell invocation for user-controlled data
- use argument arrays, not shell strings
- strict input validation and least-privilege execution contexts
