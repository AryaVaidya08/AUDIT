id: jwt-mistakes
title: JWT Validation Mistakes (CWE-347)
domain: authn_session
weakness_type: jwt_misconfiguration
cwe: CWE-347
owasp_2021: A07:Identification and Authentication Failures
exploit_classes: auth_bypass,privesc
languages: python,node,java,go,php,ruby
tags: jwt,auth,cwe-347,owasp-a07
severity_guidance: high
---
JWT vulnerabilities often come from incorrect verification logic rather than the token format itself.
Common mistakes include skipping signature validation, accepting weak algorithms, or not checking claims.

Common indicators:
- decode calls with verify=False
- acceptance of "none" algorithm or algorithm confusion
- missing exp/aud/iss checks

Impact:
- account takeover via forged tokens
- privilege escalation
- long-lived session abuse

Recommended remediation:
- enforce explicit allowed algorithms
- validate signature and all required claims
- rotate and protect signing keys
