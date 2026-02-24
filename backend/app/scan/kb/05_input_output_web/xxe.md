id: xxe
title: XML External Entity Injection (CWE-611)
domain: input_output_web
weakness_type: xxe_injection
cwe: CWE-611
owasp_2021: A05:Security Misconfiguration
exploit_classes: data_exfil,ssrf
languages: python,java,node,php,ruby
tags: cwe-611,xxe,owasp-a05,xml,injection
severity_guidance: high
---
XXE occurs when XML parsers process external entity references embedded in attacker-controlled XML.
Enabled by default in many older parsers, it can be exploited to read local files or trigger SSRF.

Common indicators:
- XML parsers used with default settings (libxml2, lxml, expat, SAX/DOM parsers)
- SOAP or XML-based APIs accepting uploads without entity disablement
- DOCTYPE declarations not stripped before parsing

Impact:
- local file disclosure (e.g., /etc/passwd, private keys)
- internal SSRF to metadata services
- denial of service via billion-laughs entity expansion

Recommended remediation:
- disable external entity processing and DTD loading in all parsers
- use safe parser presets (e.g., defusedxml in Python)
- reject or strip DOCTYPE declarations at ingestion boundaries
