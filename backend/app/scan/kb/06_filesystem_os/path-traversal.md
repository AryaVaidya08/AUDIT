id: path-traversal
title: Path Traversal (CWE-22)
domain: filesystem_os
weakness_type: path_traversal
cwe: CWE-22
owasp_2021: A01:Broken Access Control
exploit_classes: data_exfil,rce
languages: python,node,java,go,php,ruby
tags: cwe-22,path-traversal,filesystem,owasp-a01
severity_guidance: high
---
Path traversal happens when file paths are built from user input without normalization and base-path checks.
Attackers may read or overwrite sensitive files outside intended directories.

Common indicators:
- use of ../ segments from request parameters
- direct open/read calls with user-controlled filenames
- missing realpath/canonicalization checks

Impact:
- sensitive file disclosure
- arbitrary file overwrite
- possible remote code execution in chained scenarios

Recommended remediation:
- resolve and validate canonical paths under a fixed base directory
- reject traversal tokens and absolute paths
- enforce strict extension and location allowlists
