id: insecure-file-upload
title: Unrestricted File Upload (CWE-434)
domain: filesystem_os
weakness_type: unrestricted_file_upload
cwe: CWE-434
owasp_2021: A04:Insecure Design
exploit_classes: rce,stored_xss
languages: python,node,java,php,ruby
tags: cwe-434,file-upload,rce,owasp-a04
severity_guidance: high
---
Unrestricted file upload allows attackers to store and potentially execute malicious files on the server.
Risks arise when file type, content, and storage path are not properly validated.

Common indicators:
- file uploads stored in web-accessible directories without extension enforcement
- MIME type or Content-Type validated only on the client or via header alone (easily spoofed)
- uploaded filenames used directly in filesystem paths
- no virus or content scanning on uploaded files

Impact:
- web shell deployment leading to remote code execution
- stored XSS via malicious SVG, HTML, or polyglot files
- server-side path traversal through crafted filenames

Recommended remediation:
- validate file type via magic bytes, not just extension or MIME header
- store uploads outside the web root and serve through a controller
- rename files to random identifiers on disk; strip original filenames
- enforce maximum file size and content scanning where feasible
