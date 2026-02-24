id: subdomain-takeover
title: Subdomain Takeover (CWE-923)
domain: config_deploy
weakness_type: subdomain_takeover
cwe: CWE-923
owasp_2021: A05:Security Misconfiguration
exploit_classes: phishing,session_hijack
languages: python,node,java,go
tags: cwe-923,subdomain-takeover,dns,cloud,owasp-a05
severity_guidance: high
---
Subdomain takeover occurs when a DNS record points to a third-party service (GitHub Pages, S3, Heroku, Fastly) that has been deprovisioned, allowing an attacker to claim the service and serve content under the victim's subdomain.

Common indicators:
- CNAME records pointing to deprovisioned cloud services returning NXDOMAIN or unclaimed errors
- dangling DNS entries after service teardowns or migrations
- subdomains pointing to SaaS platforms that accept custom domain claims

Impact:
- phishing and credential harvesting under a trusted subdomain
- cookie theft scoped to the parent domain
- malware distribution appearing to come from a legitimate domain

Recommended remediation:
- audit and remove DNS records for decommissioned services immediately
- monitor all subdomains for dangling CNAME targets
- deprovision cloud resources and DNS records together as a single atomic operation
