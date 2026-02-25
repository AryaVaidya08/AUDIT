# audit-code

`audit-code` installs a prebuilt AUDIT binary for your OS/arch at install time.

## Install

```bash
npm i -g audit-code
audit --help
```

## How it works

- `postinstall` resolves your platform (`darwin-arm64`, `darwin-x64`, `linux-x64`, `win32-x64`).
- It downloads the matching release asset and `audit-checksums.txt`.
- It verifies SHA-256 before saving the binary into `vendor/<platform>-<arch>/`.
- `bin/audit.js` launches the binary with inherited stdio.

## Binary source override

Set `AUDIT_BINARY_BASE_URL` when testing mirrors or non-GitHub release endpoints:

```bash
export AUDIT_BINARY_BASE_URL="https://github.com/<owner>/<repo>/releases/download/v0.1.0"
```

The installer appends `/<asset>` and `/audit-checksums.txt` to that base.
