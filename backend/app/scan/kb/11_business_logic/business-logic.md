id: business-logic
title: Business Logic Vulnerabilities (CWE-840)
domain: business_logic
weakness_type: business_logic_flaw
cwe: CWE-840
owasp_2021: A04:Insecure Design
exploit_classes: integrity_violation,auth_bypass
languages: python,node,java,go,php,ruby
tags: cwe-840,business-logic,owasp-a04,api,validation
severity_guidance: high
---
Business logic flaws are application-specific vulnerabilities that arise when an attacker exploits valid functionality in unintended ways.
They are invisible to generic scanners because they require understanding of the expected application workflow.

Common indicators:
- multi-step workflows where earlier steps can be skipped (e.g., payment before verification)
- price or quantity values accepted from client without server-side recalculation
- negative quantities, zero-price items, or integer overflow in cart/financial logic
- state machine transitions not enforced server-side (order lifecycle, approval workflows)

Impact:
- financial loss through price manipulation or free goods
- bypass of approval or KYC workflows
- abuse of loyalty/reward systems

Recommended remediation:
- enforce all business rules server-side; never trust client-supplied prices or totals
- validate state transitions explicitly and reject out-of-order steps
- implement workflow integrity checks with server-stored state
