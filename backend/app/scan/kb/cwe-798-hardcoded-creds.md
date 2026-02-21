id: cwe-798-hardcoded-creds
title: Hardcoded Credentials (CWE-798)
tags: cwe-798,owasp-a07,secrets,credentials
severity_guidance: high
---
Hardcoded credentials are secret values embedded directly in source code or configuration files.
This maps to CWE-798 and often appears as API keys, tokens, passwords, private keys, or cloud access keys.

Why this is dangerous:
- secrets are exposed to every code reader
- leaked repositories become credential leaks
- rotated keys are often forgotten after compromise

Detection hints:
- variables named api_key, token, password, secret with string literals
- AWS keys like AKIA...
- PEM private key blocks in source

Recommended remediation:
- move secrets to environment variables or a secret manager
- rotate exposed credentials immediately
- add secret scanning in CI/CD
