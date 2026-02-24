id: mfa-bypass
title: Multi-Factor Authentication Bypass
domain: authn_session
weakness_type: mfa_bypass
cwe: CWE-308
owasp_2021: A07:Identification and Authentication Failures
exploit_classes: auth_bypass
languages: python,node,java,go,php,ruby
tags: cwe-308,mfa,2fa,otp,auth,owasp-a07
severity_guidance: high
---
MFA bypass occurs when the second authentication factor can be circumvented through logic flaws, response manipulation, or brute force.
Common issues include predictable OTP generation, missing server-side step validation, and fallback weaknesses.

Common indicators:
- OTP codes accepted on endpoints reachable without completing step one
- MFA validation step can be skipped by going directly to post-authentication URL
- brute-forceable 4 or 6 digit OTP without rate limiting or lockout
- response body contains is_mfa_required: true which can be manipulated client-side
- backup codes stored in plaintext or with recoverable encoding

Impact:
- full authentication bypass for all MFA-protected accounts
- account takeover despite valid second factor requirement
- phishing-resistant auth downgraded to single-factor

Recommended remediation:
- enforce MFA challenge completion as a server-side session state requirement
- apply strict rate limiting and lockout on OTP submission endpoints
- use time-based OTP with short windows and server-side replay detection
