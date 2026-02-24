id: zip-slip
title: Zip Slip / Archive Path Traversal (CWE-22)
domain: filesystem_os
weakness_type: archive_path_traversal
cwe: CWE-22
owasp_2021: A01:Broken Access Control
exploit_classes: rce,integrity_violation
languages: python,node,java,go,php,ruby
tags: cwe-22,zip-slip,archive,path-traversal,rce,owasp-a01
severity_guidance: high
---
Zip Slip is a form of path traversal triggered when archive entries contain directory traversal sequences (../../) in their filenames.
Extraction without path validation writes files to arbitrary locations on the filesystem.

Common indicators:
- archive extraction using zipfile, tarfile, or similar without validating entry paths
- no check that extracted paths resolve within the intended output directory
- automated processing pipelines that extract user-supplied archives

Impact:
- overwrite of application code or configuration files leading to RCE
- overwrite of cron jobs, startup scripts, or authorized_keys
- data destruction through overwriting critical system files

Recommended remediation:
- validate that each archive entry resolves to a canonical path within the target directory
- reject entries with absolute paths or traversal sequences (../)
- use safe extraction libraries or wrapper functions that enforce path containment
