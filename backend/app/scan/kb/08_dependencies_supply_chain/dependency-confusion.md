id: dependency-confusion
title: Dependency Confusion / Supply Chain Attack (CWE-829)
domain: dependencies_supply_chain
weakness_type: dependency_confusion
cwe: CWE-829
owasp_2021: A06:Vulnerable and Outdated Components
exploit_classes: supply_chain,rce
languages: python,node,java,ruby,go,php
tags: cwe-829,dependency-confusion,supply-chain,owasp-a06,npm,pypi
severity_guidance: high
---
Dependency confusion attacks exploit package manager resolution order to substitute a private internal package with a malicious public one of the same name but higher version.

Common indicators:
- internal package names not reserved on public registries (npm, PyPI, RubyGems)
- package managers configured to check public registry before private
- requirements files or package.json referencing packages that do not exist publicly

Impact:
- arbitrary code execution in CI/CD pipelines and developer environments
- malicious packages exfiltrating secrets or installing backdoors
- full software supply chain compromise

Recommended remediation:
- reserve all internal package names on public registries as empty stubs
- configure package managers to prefer or pin internal registry sources
- use hash-pinned lockfiles and verify package integrity in CI
