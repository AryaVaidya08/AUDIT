id: insecure-direct-function
title: Unsafe Reflection / Dynamic Function Invocation (CWE-470)
domain: business_logic
weakness_type: unsafe_reflection
cwe: CWE-470
owasp_2021: A03:Injection
exploit_classes: rce,privesc
languages: python,java,php,ruby,node
tags: cwe-470,reflection,dynamic-invocation,rce,owasp-a03
severity_guidance: high
---
Unsafe reflection occurs when user-supplied class names, method names, or function references are used to dynamically invoke code.
This can lead to unintended method execution or remote code execution via gadget invocation.

Common indicators:
- getattr(module, user_input)() in Python
- Class.forName(userInput) in Java without a strict allowlist
- PHP variable functions or call_user_func with user-controlled values
- eval or dynamic require/import of user-supplied module paths

Impact:
- invocation of unintended privileged methods
- remote code execution through method gadget chains
- arbitrary object creation and method invocation

Recommended remediation:
- never derive callable references directly from user input
- use explicit dispatch maps (allowlisted action -> handler) rather than dynamic reflection
- validate input against a strict allowlist before any reflective operation
