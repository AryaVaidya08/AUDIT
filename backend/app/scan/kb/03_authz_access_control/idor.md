id: idor
title: Insecure Direct Object Reference (CWE-639)
domain: authz_access_control
weakness_type: insecure_direct_object_reference
cwe: CWE-639
owasp_2021: A01:Broken Access Control
exploit_classes: data_exfil,privesc
languages: python,node,java,go,php,ruby
tags: idor,cwe-639,owasp-a01,access-control,authorization
severity_guidance: high
---
IDOR occurs when an application exposes internal object identifiers (IDs, filenames, keys) and fails to verify the requesting user owns or is authorized to access the referenced object.

Common indicators:
- sequential or guessable numeric IDs in URLs or request bodies
- /api/resource/{id} endpoints that fetch records without ownership check
- bulk exports or downloads keyed by user-supplied identifiers

Impact:
- horizontal privilege escalation between users
- mass data scraping of other users' private records
- modification or deletion of arbitrary records

Recommended remediation:
- enforce ownership/authorization check on every object retrieval
- prefer opaque, non-sequential identifiers (UUIDs)
- centralize authorization logic rather than rely on client-side filtering
