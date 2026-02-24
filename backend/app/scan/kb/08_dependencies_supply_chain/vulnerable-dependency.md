id: vulnerable-dependency
title: Vulnerable and Outdated Component (CWE-1104)
domain: dependencies_supply_chain
weakness_type: vulnerable_dependency
cwe: CWE-1104
owasp_2021: A06:Vulnerable and Outdated Components
exploit_classes: rce,data_exfil,dos
languages: python,node,java,go,php,ruby
tags: cwe-1104,vulnerable-dependency,cve,owasp-a06,supply-chain
severity_guidance: high
---
Using third-party libraries or frameworks with known CVEs exposes the application to publicly documented exploits.
The severity inherits from the underlying CVE and can range from low to critical.

Common indicators:
- pinned dependency versions that include known CVEs (e.g., Log4j 2.x, Spring4Shell, Struts RCE)
- requirements.txt, package.json, pom.xml, or go.mod with packages flagged by audit tools
- outdated major versions of web frameworks or serialization libraries
- no automated dependency scanning in CI/CD pipeline

Impact:
- varies by CVE: ranges from information disclosure to unauthenticated RCE
- exploitation of well-documented public exploits with available proof-of-concept
- downstream exposure of all services using the component

Recommended remediation:
- run dependency audits in CI (npm audit, pip-audit, Dependabot, Snyk)
- subscribe to CVE feeds for your technology stack
- pin and update dependencies promptly when security advisories are published
