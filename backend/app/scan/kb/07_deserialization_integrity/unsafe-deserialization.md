id: unsafe-deserialization
title: Unsafe Native Deserialization (CWE-502)
domain: deserialization_integrity
weakness_type: unsafe_native_deserialization
cwe: CWE-502
owasp_2021: A08:Software and Data Integrity Failures
exploit_classes: rce
languages: python,java,php,ruby
tags: cwe-502,deserialization,rce,owasp-a08,java,python,php
severity_guidance: critical
---
Unsafe deserialization occurs when untrusted data is passed to a native binary deserialization function that can instantiate arbitrary objects and invoke methods.
This is distinct from data-format issues and refers to language-native object serialization.

Common indicators:
- Python pickle.loads() or marshal.loads() on user-supplied bytes
- Java ObjectInputStream.readObject() processing network or session data
- PHP unserialize() on cookie or parameter values
- Ruby Marshal.load() on user-controlled input

Impact:
- remote code execution through gadget chains in classpath or module imports
- denial of service via resource exhaustion gadgets
- arbitrary object injection leading to authentication bypass

Recommended remediation:
- avoid native serialization for untrusted data entirely; use JSON or other data-only formats
- if native serialization is required, use integrity-protected serialized blobs (HMAC sign)
- apply deserialization filters/allowlists (Java ObjectInputFilter, etc.)
