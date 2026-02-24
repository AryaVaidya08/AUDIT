id: rate-limiting-absent
title: Missing Rate Limiting (CWE-770)
domain: config_deploy
weakness_type: missing_rate_limiting
cwe: CWE-770
owasp_2021: A04:Insecure Design
exploit_classes: brute_force,dos
languages: python,node,java,go,php,ruby
tags: cwe-770,rate-limiting,brute-force,owasp-a04,dos
severity_guidance: medium
---
The absence of rate limiting on sensitive endpoints allows automated abuse such as brute-forcing credentials, scraping data, or triggering expensive operations at high volume.

Common indicators:
- login, password reset, OTP, and registration endpoints without request throttling
- no HTTP 429 responses or backoff logic on high-frequency requests
- API endpoints returning large datasets without pagination or rate caps
- absence of account lockout after repeated failed authentication attempts

Impact:
- credential brute-force leading to account takeover
- OTP or MFA code enumeration
- resource exhaustion and cost amplification (SMS, email, compute)

Recommended remediation:
- apply per-IP and per-account rate limits on all authentication and sensitive endpoints
- implement exponential backoff and temporary lockout on repeated failures
- return 429 with Retry-After headers; use token-bucket or sliding-window algorithms
