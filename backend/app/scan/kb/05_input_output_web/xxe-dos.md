id: xml-bomb
title: XML Bomb / Billion Laughs Denial of Service (CWE-776)
domain: input_output_web
weakness_type: xml_entity_expansion
cwe: CWE-776
owasp_2021: A05:Security Misconfiguration
exploit_classes: dos
languages: python,java,node,php,ruby
tags: cwe-776,xml-bomb,dos,xml,owasp-a05
severity_guidance: medium
---
The billion laughs attack (XML bomb) uses recursive entity expansion in XML to exhaust parser memory and CPU.
A small document can expand to gigabytes, causing denial of service.

Common indicators:
- XML parsers that process DTDs and entity definitions without expansion limits
- SOAP or XML upload endpoints that do not restrict entity depth or expansion ratio
- parsers configured with default settings that permit recursive entity references

Impact:
- denial of service through memory exhaustion
- CPU spike causing server unresponsiveness for all users
- cascading failure in services that synchronously parse uploaded XML

Recommended remediation:
- disable DTD processing and external entity expansion in all XML parsers
- set entity expansion limits (e.g., libxml2 XML_PARSE_HUGE disabled)
- use safe parsing libraries such as defusedxml (Python) that disable these by default
