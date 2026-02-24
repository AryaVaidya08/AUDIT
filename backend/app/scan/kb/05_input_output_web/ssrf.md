id: ssrf
title: Server-Side Request Forgery (SSRF, CWE-918)
domain: input_output_web
weakness_type: server_side_request_forgery
cwe: CWE-918
owasp_2021: A10:Server-Side Request Forgery
exploit_classes: data_exfil,cloud_credential_theft
languages: python,node,java,go,php,ruby
tags: ssrf,cwe-918,owasp-a10,network
severity_guidance: high
---
SSRF occurs when user-supplied URLs are fetched by the server without strict controls.
Attackers can pivot to internal metadata services or private network hosts.

Common indicators:
- requests.get/post called on URLs directly from request parameters
- URL fetchers with weak allowlist/denylist validation
- support for arbitrary protocols or redirects

Impact:
- cloud credential theft
- internal service probing
- bypass of perimeter network controls

Recommended remediation:
- strict destination allowlists
- block internal IP ranges and metadata endpoints
- disable dangerous protocols and follow-redirect restrictions
