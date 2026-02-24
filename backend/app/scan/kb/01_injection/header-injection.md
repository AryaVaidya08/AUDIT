id: header-injection
title: HTTP Header Injection / Response Splitting (CWE-113)
domain: injection
weakness_type: header_injection
cwe: CWE-113
owasp_2021: A03:Injection
exploit_classes: session_hijack,cache_poison
languages: python,node,java,php,ruby,go
tags: cwe-113,header-injection,response-splitting,owasp-a03,web
severity_guidance: medium
---
Header injection occurs when user-controlled data is placed into HTTP response headers without stripping CRLF characters.
In response splitting, injected newlines allow the attacker to forge additional headers or body content.

Common indicators:
- Location, Set-Cookie, or custom headers constructed with user-supplied values
- redirect targets or cookie values that include unencoded \r\n sequences
- frameworks or raw WSGI/CGI handlers that do not sanitize header values

Impact:
- session fixation via injected Set-Cookie headers
- cache poisoning by injecting content into shared caches
- cross-site scripting via crafted response bodies

Recommended remediation:
- strip or reject CRLF characters (\r, \n) from all header values
- use framework-level header setting APIs that encode values automatically
- avoid placing raw user input into any HTTP header
