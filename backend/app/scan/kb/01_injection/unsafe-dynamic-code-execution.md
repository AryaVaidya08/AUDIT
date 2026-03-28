id: unsafe-dynamic-code-execution
title: Unsafe Dynamic Code Execution (CWE-94)
domain: injection
weakness_type: unsafe_dynamic_code_execution
cwe: CWE-94
owasp_2021: A03:Injection
exploit_classes: rce,data_exfil
languages: python,node,php,ruby,perl
tags: cwe-94,code-injection,eval-injection,eval,exec,rce,owasp-a03
severity_guidance: critical
---
Unsafe dynamic code execution occurs when untrusted input is executed by runtime evaluation features such as eval(), exec(), new Function(), or similar interpreter facilities.
This maps to general code injection under CWE-94. More specific eval-injection cases can also fall under CWE-95.

Common indicators:
- Python eval(user_input) or exec(user_input)
- JavaScript eval(userInput) or new Function(userInput)
- PHP eval($userInput)
- dynamic dispatch strings built from user input and executed as code

Impact:
- arbitrary code execution
- full server compromise or data exfiltration
- bypass of intended control flow or authorization logic

Recommended remediation:
- never execute user-controlled input as code
- replace dynamic evaluation with explicit dispatch tables or safe parsers
- use strict allowlists and structured parsing for data-driven behavior
