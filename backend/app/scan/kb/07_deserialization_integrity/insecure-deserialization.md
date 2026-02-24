id: insecure-deserialization
title: Insecure Deserialization (CWE-502)
domain: deserialization_integrity
weakness_type: insecure_deserialization
cwe: CWE-502
owasp_2021: A08:Software and Data Integrity Failures
exploit_classes: rce,auth_bypass
languages: python,java,node,php,ruby
tags: deserialization,cwe-502,owasp-a08,rce
severity_guidance: critical
---
Insecure deserialization occurs when untrusted data is used to reconstruct objects in a way that allows attackers to manipulate application logic or execute arbitrary code.
Many deserialization vulnerabilities arise from gadget chains in the classpath or module imports.

Common indicators:
- deserialization of data received from untrusted sources (HTTP body, cookies, message queues)
- use of native serialization formats (Java serialization, Python pickle, PHP unserialize)
- no integrity verification before deserialization
- use of YAML.load() or similar unsafe loaders

Impact:
- remote code execution via gadget chains
- authentication bypass
- privilege escalation through object manipulation

Recommended remediation:
- avoid native serialization for untrusted data; prefer JSON or Protobuf
- sign and verify serialized data with HMAC before deserializing
- apply deserialization filters/allowlists where native formats are required
