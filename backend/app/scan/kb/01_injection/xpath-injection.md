id: xpath-injection
title: XPath Injection (CWE-643)
domain: injection
weakness_type: xpath_injection
cwe: CWE-643
owasp_2021: A03:Injection
exploit_classes: data_exfil,auth_bypass
languages: java,python,php,node
tags: cwe-643,xpath-injection,xml,injection,owasp-a03
severity_guidance: high
---
XPath injection occurs when user input is concatenated into XPath query strings without escaping.
Attackers can manipulate XPath logic to bypass authentication or extract unauthorized XML data.

Common indicators:
- XPath queries built with string concatenation using request parameters
- authentication queries like //user[name='$user' and pass='$pass'] with unescaped input
- XML-backed datastores queried dynamically without parameterization

Impact:
- authentication bypass (always-true XPath conditions)
- full XML document exfiltration via boolean inference attacks
- data tampering in XML-backed storage

Recommended remediation:
- use parameterized XPath queries where the API supports them
- escape single quotes and special characters in XPath string literals
- prefer structured XML APIs over raw XPath for user-facing queries
