id: sensitive-data-exposure
title: Sensitive Data Exposure / Cleartext Transmission (CWE-319)
domain: crypto_secrets
weakness_type: cleartext_transmission
cwe: CWE-319
owasp_2021: A02:Cryptographic Failures
exploit_classes: data_exfil
languages: python,node,java,go,php,ruby
tags: cwe-319,sensitive-data,cleartext,owasp-a02,tls,pii
severity_guidance: high
---
Sensitive data exposure occurs when confidential information is transmitted or stored without encryption, or when strong encryption is misconfigured.
This includes PII, credentials, financial data, and health information.

Common indicators:
- HTTP used instead of HTTPS for any user-facing or API endpoints
- passwords or tokens stored or logged in plaintext
- sensitive fields returned in API responses but not needed by the caller
- TLS configured with old protocol versions (TLS 1.0/1.1) or weak cipher suites

Impact:
- credential and session token interception on network
- regulatory violations (GDPR, PCI-DSS, HIPAA)
- bulk PII leakage from exposed logs or storage

Recommended remediation:
- enforce HTTPS with HSTS and redirect all HTTP traffic
- store passwords using strong one-way hashing (Argon2, bcrypt)
- apply field-level minimization in API responses; do not return sensitive fields unless required
