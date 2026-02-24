id: insufficient-logging
title: Insufficient Logging and Monitoring (CWE-778)
domain: logging_monitoring
weakness_type: insufficient_logging
cwe: CWE-778
owasp_2021: A09:Security Logging and Monitoring Failures
exploit_classes: reconnaissance
languages: python,node,java,go,php,ruby
tags: cwe-778,logging,monitoring,owasp-a09,audit
severity_guidance: medium
---
Insufficient logging and monitoring means that attacks go undetected, forensic investigations lack evidence, and incident response is severely hampered.
OWASP considers this a top-10 risk due to its prevalence and the downstream impact on breach detection.

Common indicators:
- authentication events (login, logout, failure) not logged
- no logging of authorization failures or access control violations
- log entries missing timestamps, user identifiers, or source IPs
- no alerting or monitoring connected to application logs

Impact:
- extended attacker dwell time before detection
- inability to determine scope and timeline of a breach
- regulatory non-compliance (PCI-DSS, SOC 2, HIPAA audit requirements)

Recommended remediation:
- log all authentication events, authorization failures, and input validation errors
- include structured fields: timestamp, user ID, source IP, action, resource, outcome
- integrate logs with a SIEM or alerting system with detection rules for anomalous activity
