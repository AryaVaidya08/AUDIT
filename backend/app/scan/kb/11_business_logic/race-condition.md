id: race-condition
title: Race Condition / TOCTOU (CWE-367)
domain: business_logic
weakness_type: race_condition
cwe: CWE-367
owasp_2021: A04:Insecure Design
exploit_classes: integrity_violation,auth_bypass
languages: python,node,java,go,php,ruby
tags: cwe-367,race-condition,toctou,concurrency,owasp-a04
severity_guidance: medium
---
Race conditions occur when two concurrent operations rely on shared state that is checked and then used without atomicity.
TOCTOU (time-of-check/time-of-use) gaps allow an attacker to change state between the check and the action.

Common indicators:
- balance or quota checks followed by non-atomic deductions outside a transaction
- file existence checks (os.path.exists) before open/unlink in multi-threaded contexts
- coupon or one-time-use token validation without database-level locking

Impact:
- double-spend and negative balance exploitation in payment systems
- multiple redemptions of single-use tokens or discount codes
- privilege escalation via concurrent role updates

Recommended remediation:
- perform check and update atomically using database transactions and SELECT FOR UPDATE
- use idempotency keys for sensitive operations
- apply rate limiting and deduplication for concurrent request patterns
