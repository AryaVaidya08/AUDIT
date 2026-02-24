id: oauth-misconfig
title: OAuth 2.0 Misconfiguration (CWE-303)
domain: authn_session
weakness_type: oauth_misconfiguration
cwe: CWE-303
owasp_2021: A07:Identification and Authentication Failures
exploit_classes: auth_bypass,token_theft
languages: python,node,java,go,php,ruby
tags: cwe-303,oauth,owasp-a07,auth,token
severity_guidance: high
---
OAuth 2.0 implementations are frequently misconfigured, leading to token theft, account takeover, or authorization code interception.
Common mistakes include open redirect_uri matching, missing state parameter, and implicit flow misuse.

Common indicators:
- redirect_uri validated with prefix match or substring instead of exact match
- state parameter absent or not verified, enabling CSRF on the authorization flow
- access tokens returned in URL fragments and logged in server access logs
- client_secret hardcoded in mobile or single-page application source code

Impact:
- authorization code interception via open redirect chaining
- account takeover through forged authorization flows
- token leakage via referrer headers or server logs

Recommended remediation:
- enforce exact redirect_uri matching on the authorization server
- require and validate the state parameter as a CSRF protection mechanism
- use PKCE (Proof Key for Code Exchange) for public clients
- never embed client_secret in client-side or mobile code
