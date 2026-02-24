id: api-key-exposure
title: API Key and Token Exposure in Client-Side Code
domain: crypto_secrets
weakness_type: client_side_secret_exposure
cwe: CWE-312
owasp_2021: A02:Cryptographic Failures
exploit_classes: auth_bypass,data_exfil
languages: javascript,typescript,swift,kotlin
tags: secrets,api-key,owasp-a02,javascript,mobile,frontend
severity_guidance: high
---
API keys and tokens embedded in client-side JavaScript, mobile app binaries, or public repositories are trivially extractable by anyone who examines the code.
Unlike server-side secrets, client-side exposure guarantees the key reaches adversaries.

Common indicators:
- API keys, OAuth client secrets, or service credentials assigned as JavaScript constants
- .env files or config files committed to public repositories
- mobile apps with keys embedded in strings, plists, or compiled resources
- browser requests revealing secret keys in Authorization headers to public APIs

Impact:
- unauthorized use of paid APIs incurring financial cost
- access to third-party services (SMS, email, cloud storage) on behalf of the victim
- full backend API access if the key is for an internal service

Recommended remediation:
- never include secret keys in client-side code; proxy sensitive API calls through the backend
- use secret scanning in CI/CD to detect accidental commits
- restrict API keys to minimum necessary permissions and specific IP ranges where possible
