id: auth-missing-middleware
title: Missing Authentication or Authorization Middleware
tags: auth,access-control,owasp-a01,cwe-306
severity_guidance: high
---
Protected actions must enforce authentication and authorization checks.
Missing middleware or missing decorator checks can expose administrative or sensitive routes.

Common indicators:
- route handlers lacking auth guards in frameworks that require explicit middleware
- sensitive endpoints callable without session/token validation
- role checks missing for privileged operations

Impact:
- unauthorized data access
- privilege escalation
- administrative control takeover

Recommended remediation:
- enforce default-deny route policy
- centralize auth middleware/dependencies
- add route-level authorization tests
