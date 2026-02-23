# demo_vuln_repo

This repository is intentionally vulnerable for scanner smoke tests.

Included examples:
- hardcoded secret (`vuln_app.py`)
- SQL injection (`vuln_app.py`)
- missing auth check on admin route (`routes.js`)
- unsafe eval/deserialization (`vuln_app.py`)
