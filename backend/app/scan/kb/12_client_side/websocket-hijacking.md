id: websocket-hijacking
title: Cross-Site WebSocket Hijacking (CSWSH)
domain: client_side
weakness_type: websocket_hijacking
cwe: CWE-352
owasp_2021: A01:Broken Access Control
exploit_classes: data_exfil,session_hijack
languages: javascript,typescript,node,python,java,go
tags: websocket,cswsh,csrf,owasp-a01,web,auth
severity_guidance: high
---
Cross-Site WebSocket Hijacking allows an attacker-controlled page to establish a WebSocket connection to a target server using the victim's cookies, because browsers send cookies on WebSocket upgrade requests.

Common indicators:
- WebSocket handshake does not validate the Origin header
- authentication relies solely on cookies with no CSRF token or secondary check
- sensitive data or commands transmitted over unauthenticated WebSocket channels

Impact:
- real-time data exfiltration through a hijacked WebSocket connection
- sending unauthorized commands or messages as the authenticated user
- full session-level impersonation over persistent connections

Recommended remediation:
- validate the Origin header against an allowlist during the WebSocket handshake
- require an explicit CSRF token or ticket passed in the upgrade request
- authenticate at the application layer inside the WebSocket protocol, not solely via cookies
