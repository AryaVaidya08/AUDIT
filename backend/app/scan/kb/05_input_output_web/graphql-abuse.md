id: graphql-abuse
title: GraphQL Introspection and Query Abuse
domain: input_output_web
weakness_type: graphql_abuse
cwe: CWE-400
owasp_2021: A05:Security Misconfiguration
exploit_classes: data_exfil,dos
languages: node,python,java,go,ruby
tags: graphql,introspection,owasp-a05,api,dos
severity_guidance: medium
---
GraphQL APIs expose unique risks including schema disclosure via introspection, deeply nested query attacks, and unbounded batching.
These can be exploited to enumerate the data model or exhaust server resources.

Common indicators:
- introspection enabled in production environments
- no query depth or complexity limits enforced
- batched query arrays accepted without per-batch rate limiting
- field-level authorization missing (resolver trusts caller implicitly)

Impact:
- full schema enumeration enabling targeted injection or IDOR
- denial of service via deeply nested or aliased queries
- data exfiltration through batched requests bypassing per-request rate limits

Recommended remediation:
- disable introspection in production or restrict to authenticated admins
- enforce maximum query depth and complexity scores
- apply per-operation rate limiting; disable query batching or cap batch size
