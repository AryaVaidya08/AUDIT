id: insecure-deserialization
title: Insecure Deserialization (CWE-502)
tags: cwe-502,deserialization,pickle,yaml,owasp-a08
severity_guidance: high
---
Insecure deserialization occurs when untrusted data is deserialized into executable object graphs.
Examples include unsafe pickle loads and yaml.load with unsafe loaders.

Common indicators:
- pickle.loads on external input
- yaml.load without SafeLoader
- custom deserializers executing constructors or hooks

Impact:
- remote code execution
- logic abuse and privilege escalation
- denial of service from crafted payloads

Recommended remediation:
- avoid deserializing untrusted data into executable object types
- use safe parsers/loaders (for example yaml.safe_load)
- validate and sign serialized payloads when required
