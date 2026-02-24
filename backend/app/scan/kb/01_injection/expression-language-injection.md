id: expression-language-injection
title: Expression Language Injection (CWE-917)
domain: injection
weakness_type: expression_language_injection
cwe: CWE-917
owasp_2021: A03:Injection
exploit_classes: rce,data_exfil
languages: java,python,node
tags: cwe-917,el-injection,spel,ognl,jinja2,owasp-a03,rce
severity_guidance: critical
---
Expression Language (EL) injection occurs when user input is evaluated by an expression engine such as Spring SpEL, OGNL (Struts), Thymeleaf, or Mvel.
This commonly leads to remote code execution because EL engines can access Java reflection and runtime APIs.

Common indicators:
- user input passed to ExpressionParser.parseExpression() in Spring
- OGNL evaluation in Struts action parameters without sandboxing
- Thymeleaf template fragments built from request parameters
- ${user_input} evaluated in server-side contexts

Impact:
- remote code execution via EL engine's reflection and runtime access
- full server compromise
- environment variable and classpath enumeration

Recommended remediation:
- never pass user-controlled data as the expression source to EL engines
- apply sandbox restrictions on EL evaluators where the framework provides them
- upgrade Struts, Spring, and Thymeleaf to versions with EL injection fixes
