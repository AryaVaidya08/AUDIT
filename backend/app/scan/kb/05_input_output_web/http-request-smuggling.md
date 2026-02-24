id: http-request-smuggling
title: HTTP Request Smuggling (CWE-444)
domain: input_output_web
weakness_type: http_request_smuggling
cwe: CWE-444
owasp_2021: A05:Security Misconfiguration
exploit_classes: auth_bypass,cache_poison,session_hijack
languages: python,node,java,go,php
tags: cwe-444,http-smuggling,request-smuggling,owasp-a05,web
severity_guidance: high
---
HTTP request smuggling exploits discrepancies between how front-end and back-end servers interpret chunked and Content-Length headers, allowing attackers to inject requests that appear to originate from other users.

Common indicators:
- HTTP/1.1 pipelining through reverse proxy (nginx, HAProxy, CDN) to backend that also parses headers
- conflicting Transfer-Encoding and Content-Length headers not rejected by the pipeline
- backend servers accepting requests with ambiguous chunked encoding (TE.CL or CL.TE variants)

Impact:
- request hijacking to capture another user's credentials or session tokens
- cache poisoning to serve attacker-controlled content to all users
- bypass of security controls enforced only at the front-end layer

Recommended remediation:
- normalize and reject ambiguous Transfer-Encoding / Content-Length combinations at the proxy
- disable HTTP/1.1 keepalive pipelining between proxy and backend where feasible
- use HTTP/2 end-to-end to eliminate chunked encoding ambiguity
- keep reverse proxy and application server versions patched
