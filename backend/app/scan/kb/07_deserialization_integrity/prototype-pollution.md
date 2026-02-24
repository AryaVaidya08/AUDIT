id: prototype-pollution
title: Prototype Pollution (CWE-1321)
domain: deserialization_integrity
weakness_type: prototype_pollution
cwe: CWE-1321
owasp_2021: A08:Software and Data Integrity Failures
exploit_classes: privesc,rce,dos
languages: javascript,typescript,node
tags: cwe-1321,prototype-pollution,javascript,nodejs,owasp-a03
severity_guidance: high
---
Prototype pollution allows attackers to inject properties onto JavaScript Object.prototype, affecting all objects in the process.
It often arises from unsafe deep-merge, clone, or path-setting utilities operating on user-supplied keys.

Common indicators:
- recursive merge or set functions accepting __proto__, constructor, or prototype as keys
- lodash _.merge / _.set called with unsanitized paths from request bodies
- JSON parse followed by blind property assignment without key allowlist

Impact:
- property injection into all objects (e.g., isAdmin: true)
- denial of service through breaking built-in methods
- remote code execution when polluted properties reach eval or child_process sinks

Recommended remediation:
- deny __proto__, constructor, and prototype keys at input parsing
- use Object.create(null) for dictionaries that merge user data
- keep lodash and merge utilities updated; use Object.freeze(Object.prototype) in critical paths
