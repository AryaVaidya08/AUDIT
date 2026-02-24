id: session-fixation
title: Session Fixation (CWE-384)
domain: authn_session
weakness_type: session_fixation
cwe: CWE-384
owasp_2021: A07:Identification and Authentication Failures
exploit_classes: session_hijack
languages: python,node,java,php,ruby
tags: cwe-384,session-fixation,session,auth,owasp-a07
severity_guidance: high
---
Session fixation occurs when an application accepts externally-supplied session identifiers or fails to rotate session IDs on privilege change.
An attacker can pre-set a known session ID and hijack the session after the victim authenticates.

Common indicators:
- session ID accepted from URL parameters (JSESSIONID, PHPSESSID in query strings)
- session ID not regenerated after successful login
- session persists through logout without invalidation

Impact:
- session hijacking after attacker-controlled session ID is used
- impersonation of authenticated users
- persistent access after password change if sessions not invalidated

Recommended remediation:
- always regenerate session ID on authentication events (login, role elevation)
- invalidate all existing sessions on logout and password change
- never accept session identifiers from URL parameters
