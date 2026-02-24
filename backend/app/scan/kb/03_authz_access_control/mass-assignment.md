id: mass-assignment
title: Mass Assignment / Parameter Binding (CWE-915)
domain: authz_access_control
weakness_type: mass_assignment
cwe: CWE-915
owasp_2021: A04:Insecure Design
exploit_classes: privesc,integrity_violation
languages: python,node,java,ruby,php
tags: cwe-915,mass-assignment,owasp-a04,api,authorization
severity_guidance: high
---
Mass assignment occurs when request body fields are bound directly to model or database objects without filtering.
Attackers can set privileged fields (role, is_admin, balance) that were never intended to be user-controlled.

Common indicators:
- ORM update calls using **kwargs or spreading entire request body
- User.update_from_dict(request.json) without a field allowlist
- Django/Rails/Spring models with no attr_accessible or DTO restrictions

Impact:
- privilege escalation by setting role or admin flags
- account balance manipulation in financial applications
- overwriting internal or relational fields

Recommended remediation:
- define explicit allowlists of fields permitted from user input
- use DTOs or form objects to separate external input from internal models
- audit ORM mass-assignment shortcuts in all update paths
