id: redos
title: Regular Expression Denial of Service (CWE-1333)
domain: business_logic
weakness_type: regex_denial_of_service
cwe: CWE-1333
owasp_2021: A04:Insecure Design
exploit_classes: dos
languages: python,node,java,go,php,ruby
tags: cwe-1333,redos,dos,regex,owasp-a05
severity_guidance: medium
---
ReDoS exploits catastrophic backtracking in regular expressions when evaluated against specially crafted inputs.
Vulnerable patterns with nested quantifiers or alternation can cause exponential evaluation time.

Common indicators:
- regex patterns with nested repetition: (a+)+, (a|a)*, ([a-zA-Z]+)*
- user-supplied strings evaluated by complex regexes in request validation
- email, URL, or date validators with ambiguous backtracking patterns

Impact:
- event loop blocking in Node.js or thread starvation in synchronous servers
- denial of service with a single crafted request
- service degradation affecting all concurrent users

Recommended remediation:
- audit regex patterns for catastrophic backtracking using tools like safe-regex or recheck
- apply input length limits before regex evaluation
- use linear-time regex engines (RE2, Rust regex) for untrusted input
