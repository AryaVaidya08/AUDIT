# ShopApp — Intentionally Vulnerable Codebase

This is a synthetic, intentionally vulnerable e-commerce application built for testing security defect detection tooling. It is **not safe to run** in any real environment. Every vulnerability is deliberate.

---

## Project Structure

```
testProject/
├── src/
│   ├── app.js              Express HTTP server and route handlers
│   ├── auth.js             Authentication, token generation, password management
│   ├── db.js               Database connection pool and query helpers
│   ├── fileManager.js      File read/write/delete/archive operations
│   ├── middleware.js       CORS, rate limiting, auth middleware
│   ├── payments.js         Payment processing and card storage
│   └── websocket.js        WebSocket server and real-time messaging
├── public/
│   ├── index.html          Main frontend page
│   └── admin.js            Admin panel JavaScript
├── admin/
│   └── panel.html          Admin panel HTML
├── config/
│   └── settings.js         Application configuration
├── scripts/
│   ├── api_server.py       Flask REST API
│   ├── data_processor.py   Data transformation utilities
│   ├── generate_report.py  Report generation script
│   ├── setup_db.sql        Database schema and seed data
│   └── cron_jobs.sh        Scheduled maintenance scripts
└── package.json
```

---

## Vulnerability Index

### 1. SQL Injection

**Severity:** Critical

Raw user input is concatenated directly into SQL strings throughout the codebase, with no parameterization or escaping.

| File | Location | Description |
|---|---|---|
| [src/app.js](src/app.js) | `/login` route | Username and password injected into `SELECT` query |
| [src/app.js](src/app.js) | `/user/profile` route | `id` query param injected into `WHERE id = ${userId}` |
| [src/app.js](src/app.js) | `/search` route | Search term injected into `LIKE '%${term}%'` |
| [src/app.js](src/app.js) | `/comment` route | `postId` and `userId` injected into `INSERT` |
| [src/app.js](src/app.js) | `/admin/users` route | `role` query param injected into `WHERE role = '${role}'` |
| [src/app.js](src/app.js) | `/admin/delete-user` route | `id` injected into `DELETE WHERE id = ${userId}` |
| [src/db.js](src/db.js) | `getUserByUsername()` | Username string-interpolated directly into query |
| [src/db.js](src/db.js) | `getProductById()` | ID injected into `WHERE id = ${id}` |
| [src/db.js](src/db.js) | `searchUsers()` | Search term injected into `LIKE` on both username and email |
| [src/db.js](src/db.js) | `logActivity()` | All parameters injected into `INSERT` |
| [src/auth.js](src/auth.js) | `register()` | Username, password, email injected into `INSERT` |
| [src/auth.js](src/auth.js) | `resetPassword()` | Email and password injected into `UPDATE` |
| [src/payments.js](src/payments.js) | `storePaymentMethod()` | userId, expiry, cvv injected into `INSERT` |
| [src/payments.js](src/payments.js) | `getTransactionHistory()` | userId, startDate, endDate injected into `SELECT` |
| [src/payments.js](src/payments.js) | `refund()` | transactionId injected into `SELECT` and `UPDATE` |
| [src/websocket.js](src/websocket.js) | `chat` message handler | Room ID, sender ID, and text injected into `INSERT` |
| [src/websocket.js](src/websocket.js) | `get_history` handler | Room name and limit injected into `SELECT` |
| [src/websocket.js](src/websocket.js) | `search_users` handler | Search term injected into `LIKE` |
| [scripts/api_server.py](scripts/api_server.py) | `/api/users` | Username concatenated into `SELECT` |
| [scripts/api_server.py](scripts/api_server.py) | `/api/products/search` | Both `q` and `category` injected into `SELECT` |
| [scripts/api_server.py](scripts/api_server.py) | `/api/password-reset` | Email and token injected into `SELECT` and `UPDATE` |
| [scripts/api_server.py](scripts/api_server.py) | `/login` | Username and hashed password injected into query |
| [scripts/api_server.py](scripts/api_server.py) | `/api/report` | `type` and `date` params injected into `SELECT` |
| [scripts/data_processor.py](scripts/data_processor.py) | `run_db_query()` | Caller-supplied filter appended directly to `SELECT` |
| [scripts/data_processor.py](scripts/data_processor.py) | `store_audit_log()` | user_id and action injected into `INSERT` |
| [scripts/setup_db.sql](scripts/setup_db.sql) | `GRANT` statements | Wildcard grants to all hosts (`'%'`) with plaintext passwords |

**Also present:** `multipleStatements: true` is enabled on the MySQL pool in [src/db.js](src/db.js), allowing stacked queries.

---

### 2. Command Injection

**Severity:** Critical

User-controlled values are passed directly to shell commands via `exec()`, `os.system()`, `subprocess`, or shell-interpolated strings.

| File | Location | Description |
|---|---|---|
| [src/app.js](src/app.js) | `/ping` route | `host` body param passed to `ping -c 3 ${host}` |
| [src/app.js](src/app.js) | `/report` route | `name` query param appended to `python3 scripts/generate_report.py ${reportName}` |
| [src/fileManager.js](src/fileManager.js) | `deleteFile()` | `filename` interpolated into `rm -f ${target}` |
| [src/fileManager.js](src/fileManager.js) | `extractArchive()` | `archive` and `destination` interpolated into `tar -xf` |
| [src/fileManager.js](src/fileManager.js) | `previewImage()` | `imgPath` passed to `convert ${imgPath}` |
| [src/fileManager.js](src/fileManager.js) | `getFileInfo()` | `filename` passed to `file ${filename} && stat ${filename}` |
| [src/fileManager.js](src/fileManager.js) | `compressDirectory()` | `dir` and `output` params interpolated into `zip -r` |
| [src/websocket.js](src/websocket.js) | `admin_command` handler | `msg.command` passed directly to `exec()` |
| [scripts/api_server.py](scripts/api_server.py) | `/api/run` | `command` JSON field passed to `subprocess.check_output(cmd, shell=True)` |
| [scripts/api_server.py](scripts/api_server.py) | `/api/image-resize` | `source`, `width`, `height` interpolated into `convert` command |
| [scripts/api_server.py](scripts/api_server.py) | `/api/admin/backup` | `destination` interpolated into `mysqldump` command |
| [scripts/api_server.py](scripts/api_server.py) | `/api/execute-script` | `script` and `args` concatenated into a shell command |
| [scripts/api_server.py](scripts/api_server.py) | `/api/grep` | `pattern` and `file` interpolated into `grep` shell command |
| [scripts/data_processor.py](scripts/data_processor.py) | `parse_csv_report()` | `report_path` interpolated into `awk` shell command |
| [scripts/data_processor.py](scripts/data_processor.py) | `backup_to_remote()` | `local_path`, `remote_host`, `remote_path` interpolated into `scp` |
| [scripts/data_processor.py](scripts/data_processor.py) | `generate_invoice_pdf()` | `order_id` and `customer_name` interpolated into `wkhtmltopdf` |
| [scripts/generate_report.py](scripts/generate_report.py) | `run_report_script()` | `script_name` and `params` interpolated into `python3` shell command |
| [scripts/generate_report.py](scripts/generate_report.py) | `save_report()` | `report_name` interpolated into `chmod` via `os.system()` |
| [scripts/generate_report.py](scripts/generate_report.py) | `email_report()` | `recipient` and `filepath` interpolated into `mail` command |
| [scripts/cron_jobs.sh](scripts/cron_jobs.sh) | `process_user_uploads()` | `filename` from disk used in `eval "process_file_$filename"` |

---

### 3. Cross-Site Scripting (XSS)

**Severity:** High

User-supplied content is rendered as HTML without sanitization, in both reflected and stored forms.

| File | Location | Description |
|---|---|---|
| [src/app.js](src/app.js) | `/search` route | `term` query param reflected directly into HTML response |
| [src/app.js](src/app.js) | `/post` route | Comment `body` from database rendered into HTML without escaping |
| [src/app.js](src/app.js) | `/logs` route | Log file contents rendered inside `<pre>` tags |
| [public/index.html](public/index.html) | `msg` URL param | `params.get('message')` assigned to `innerHTML` |
| [public/index.html](public/index.html) | `loadProfile()` | `data.username`, `data.email`, `data.role` concatenated into `innerHTML` |
| [public/index.html](public/index.html) | `postComment()` | Comment `text` appended to DOM via `innerHTML +=` |
| [public/index.html](public/index.html) | `loadComments()` | `c.body` from API assigned to `div.innerHTML` |
| [public/index.html](public/index.html) | `loadUserPrefs()` | `prefs.username` from cookie assigned to `innerHTML` |
| [public/admin.js](public/admin.js) | `loadAllUsers()` | `u.username`, `u.email`, `u.password`, `u.id` injected via template literals into `innerHTML` |
| [public/admin.js](public/admin.js) | `searchUsers()` | `u.username`, `u.email`, `u.ssn` injected into `innerHTML` via `.map()` |
| [admin/panel.html](admin/panel.html) | `fetchLogs()` | Server response assigned directly to `innerHTML` |
| [admin/panel.html](admin/panel.html) | `loadPageContent()` (via admin.js) | Server HTML response assigned to `innerHTML` |

---

### 4. Insecure Deserialization

**Severity:** Critical

Untrusted serialized objects are deserialized directly, enabling remote code execution.

| File | Location | Description |
|---|---|---|
| [src/app.js](src/app.js) | `/import-settings` route | `node-serialize` deserializes raw user-supplied body |
| [scripts/api_server.py](scripts/api_server.py) | `/api/deserialize` | `pickle.loads()` called on raw request body |
| [scripts/api_server.py](scripts/api_server.py) | `/api/load-config` | `yaml.load()` with `Loader=yaml.Loader` (unsafe full loader) |
| [scripts/data_processor.py](scripts/data_processor.py) | `load_user_object()` | `pickle.loads()` on caller-supplied bytes |
| [scripts/generate_report.py](scripts/generate_report.py) | `load_cached_report()` | `pickle.load()` on a file whose name is derived from user input |
| [scripts/generate_report.py](scripts/generate_report.py) | `decode_report_data()` | Base64-decodes then `pickle.loads()` stdin data |

---

### 5. Server-Side Template Injection (SSTI)

**Severity:** Critical

User-controlled strings are evaluated as code or rendered as templates server-side.

| File | Location | Description |
|---|---|---|
| [src/app.js](src/app.js) | `/template` route | User `template` body param evaluated with `eval(\`${userTemplate}\`)` |
| [src/websocket.js](src/websocket.js) | `eval` message handler | `msg.code` passed directly to `eval()` |
| [scripts/api_server.py](scripts/api_server.py) | `/api/render` | User-supplied `template` string passed to `jinja2.Template()` and rendered |
| [scripts/data_processor.py](scripts/data_processor.py) | `render_email_template()` | Template string evaluated via `eval(f'f"""{template_str}"""')` |
| [scripts/generate_report.py](scripts/generate_report.py) | `format_report()` | Report template evaluated via `eval(f'f"""{template}"""')` |
| [scripts/data_processor.py](scripts/data_processor.py) | `process_user_data()` | User input written to a `.py` file and executed with `python3` |

---

### 6. Hardcoded Secrets and Credentials

**Severity:** High

Credentials, API keys, and cryptographic secrets are embedded in source code and scripts.

| File | Secret |
|---|---|
| [config/settings.js](config/settings.js) | MySQL password `Admin1234!`, Redis password, JWT secret, AWS access key + secret, SMTP password, Stripe live secret key, Stripe webhook secret, Twilio auth token, static AES key and IV `0000000000000000` |
| [src/app.js](src/app.js) | MySQL password `Admin1234!` hardcoded in connection config |
| [src/auth.js](src/auth.js) | JWT secret `'secret'` |
| [src/payments.js](src/payments.js) | Stripe live secret key `sk_live_...` |
| [scripts/api_server.py](scripts/api_server.py) | MySQL password, AWS secret key, Stripe live key, SendGrid API key |
| [scripts/data_processor.py](scripts/data_processor.py) | DB host/user/password dict, Stripe live key, SendGrid API key |
| [scripts/cron_jobs.sh](scripts/cron_jobs.sh) | MySQL password `Admin1234!`, remote backup password, SendGrid API key in `curl` command |
| [scripts/setup_db.sql](scripts/setup_db.sql) | MySQL grant passwords in plaintext |
| [public/admin.js](public/admin.js) | JWT admin token hardcoded as a JS constant `API_TOKEN` |

---

### 7. Path Traversal

**Severity:** High

File paths constructed from user input allow reading arbitrary files outside the intended directory.

| File | Location | Description |
|---|---|---|
| [src/app.js](src/app.js) | `/file` route | `name` query param joined with `../uploads` without normalization |
| [src/app.js](src/app.js) | `/logs` route | `date` param used to construct log file path directly |
| [src/fileManager.js](src/fileManager.js) | `readUserFile()` | `req.query.file` joined with `BASE_DIR` using `path.join` without validation |
| [src/fileManager.js](src/fileManager.js) | `serveStaticFile()` | `path.resolve()` used but without checking the result is within the intended root |
| [scripts/api_server.py](scripts/api_server.py) | `/api/file` | `path` query param passed directly to `open()` |
| [scripts/generate_report.py](scripts/generate_report.py) | `get_report_template()` | `template_name` injected into `templates/{template_name}.html` path |
| [scripts/generate_report.py](scripts/generate_report.py) | `load_cached_report()` | Cache file path derived from user-controlled hash value |

---

### 8. Server-Side Request Forgery (SSRF)

**Severity:** High

User-controlled URLs are fetched server-side with no allow-list validation.

| File | Location | Description |
|---|---|---|
| [scripts/api_server.py](scripts/api_server.py) | `/api/fetch` | `url` JSON field passed directly to `urllib.request.urlopen()` |
| [scripts/data_processor.py](scripts/data_processor.py) | `fetch_external_data()` | `endpoint` param appended to internal URL and fetched |
| [scripts/generate_report.py](scripts/generate_report.py) | `fetch_external_report()` | `url` param passed directly to `urllib.request.urlopen()` |
| [src/payments.js](src/payments.js) | `processPayment()` | `rejectUnauthorized: false` disables TLS verification on outbound HTTPS call |

---

### 9. Broken Authentication

**Severity:** High

Multiple flaws in authentication allow bypass, token forgery, or weak credential handling.

| File | Location | Description |
|---|---|---|
| [src/auth.js](src/auth.js) | `verifyToken()` | `algorithms: ['HS256', 'none']` allows the `none` algorithm, bypassing signature verification |
| [src/middleware.js](src/middleware.js) | `authRequired()` | Same `none` algorithm accepted |
| [src/websocket.js](src/websocket.js) | Connection handler | `algorithms: ['HS256', 'none']` accepted on WebSocket token |
| [src/auth.js](src/auth.js) | `JWT_SECRET` | Secret is the string `'secret'` — trivially brute-forceable |
| [src/auth.js](src/auth.js) | `generateToken()` | Tokens issued with `expiresIn: '365d'` — effectively non-expiring |
| [src/auth.js](src/auth.js) | `resetPasswordRequest()` | Reset token generated with `Math.random()` (not cryptographically secure), stored in memory only |
| [src/auth.js](src/auth.js) | `resetPassword()` | Token compared with `==` (loose equality) instead of a constant-time comparison |
| [src/middleware.js](src/middleware.js) | `adminRequired()` | `x-admin-override: true` header bypasses admin check entirely |
| [src/app.js](src/app.js) | `/admin/delete-user` | No authentication middleware on destructive admin route |
| [public/admin.js](public/admin.js) | `impersonateUser()` | Auth token and role stored in `localStorage` — accessible to XSS |

---

### 10. Weak Cryptography

**Severity:** High

Broken or improperly configured cryptographic functions used for sensitive operations.

| File | Location | Description |
|---|---|---|
| [src/auth.js](src/auth.js) | `hashPassword()` | Passwords hashed with MD5 — no salt, broken algorithm |
| [src/auth.js](src/auth.js) | `generateApiKey()` | API keys derived via SHA-1 with a hardcoded static salt |
| [src/payments.js](src/payments.js) | `encryptCard()` / `decryptCard()` | AES-128-CBC with a static all-zero key `'0000000000000000'` and IV |
| [src/payments.js](src/payments.js) | `generateReceiptToken()` | Receipt tokens generated with MD5 |
| [scripts/api_server.py](scripts/api_server.py) | `/api/password-reset` | New passwords hashed with MD5 |
| [scripts/data_processor.py](scripts/data_processor.py) | `hash_sensitive_data()` | MD5 used for sensitive data hashing |
| [scripts/data_processor.py](scripts/data_processor.py) | `generate_temp_password()` | Temp passwords generated from MD5 of a predictable seed |
| [scripts/generate_report.py](scripts/generate_report.py) | `generate_report_hash()` | Report cache keys generated with MD5 |
| [scripts/setup_db.sql](scripts/setup_db.sql) | Seed data | User passwords stored as unsalted MD5 hashes (`21232f29...` = `admin`) |

---

### 11. Cross-Site Request Forgery (CSRF)

**Severity:** Medium

State-changing endpoints accept requests from any origin with no CSRF token validation.

| File | Location | Description |
|---|---|---|
| [src/app.js](src/app.js) | `/comment`, `/login`, `/upload`, `/ping`, `/import-settings` | No CSRF token required on POST routes |
| [src/middleware.js](src/middleware.js) | `corsHandler()` | Reflects request `Origin` header back unconditionally with `Access-Control-Allow-Credentials: true` |
| [config/settings.js](config/settings.js) | `cors.origin` | Set to `'*'` globally |
| [src/app.js](src/app.js) | Session cookie | `httpOnly: false` and `secure: false` on session cookie |

---

### 12. Insecure Direct Object Reference (IDOR)

**Severity:** High

Object identifiers are taken directly from user input with no ownership or authorization check.

| File | Location | Description |
|---|---|---|
| [src/app.js](src/app.js) | `/user/profile` | Any `id` query param returns that user's full record |
| [src/app.js](src/app.js) | `/admin/delete-user` | Any `id` in body deletes that user — no session check |
| [src/payments.js](src/payments.js) | `getTransactionHistory()` | `user_id` query param returns any user's transactions |
| [src/payments.js](src/payments.js) | `refund()` | `transaction_id` body param processes refund for any transaction |
| [public/admin.js](public/admin.js) | `deleteUser()` | Client-controlled `userId` sent to delete endpoint |

---

### 13. Sensitive Data Exposure

**Severity:** High

Sensitive fields are returned to clients, logged, or stored insecurely.

| File | Location | Description |
|---|---|---|
| [src/db.js](src/db.js) | `searchUsers()` | Returns `password`, `ssn`, `credit_card` columns |
| [src/payments.js](src/payments.js) | `storePaymentMethod()` | Raw CVV stored in the database |
| [public/admin.js](public/admin.js) | `loadAllUsers()` | Password hash rendered in the admin table HTML |
| [public/admin.js](public/admin.js) | `searchUsers()` | SSN rendered in search results DOM |
| [scripts/cron_jobs.sh](scripts/cron_jobs.sh) | `generate_reports()` | SSN and credit card exported to world-readable CSV files |
| [scripts/setup_db.sql](scripts/setup_db.sql) | Schema | `ssn` and `credit_card` columns defined on the users table |
| [src/middleware.js](src/middleware.js) | `requestLogger()` | Full request body (including passwords) logged to console |
| [scripts/api_server.py](scripts/api_server.py) | `app.run(debug=True)` | Flask debug mode enabled in production — exposes interactive debugger |

---

### 14. Zip Slip (Archive Path Traversal)

**Severity:** High

Archive extraction routines do not validate member paths, allowing files to be written outside the destination directory.

| File | Location | Description |
|---|---|---|
| [scripts/data_processor.py](scripts/data_processor.py) | `extract_zip()` | `zipfile.ZipFile.extractall()` with no member path validation |
| [scripts/data_processor.py](scripts/data_processor.py) | `extract_tar()` | `tarfile.open().extractall()` with no member path validation |
| [src/fileManager.js](src/fileManager.js) | `extractArchive()` | `tar -xf` with user-controlled archive and destination paths |

---

### 15. Open Redirect

**Severity:** Medium

Redirect targets are taken directly from user input with no validation.

| File | Location | Description |
|---|---|---|
| [src/app.js](src/app.js) | `/redirect` route | `url` query param passed to `res.redirect()` without validation |
| [public/index.html](public/index.html) | `handleRedirect()` | `next` URL param assigned to `window.location.href` |

---

### 16. Missing Rate Limiting

**Severity:** Medium

The rate limiting middleware is stubbed and does nothing, leaving all endpoints open to brute force and DoS.

| File | Location | Description |
|---|---|---|
| [src/middleware.js](src/middleware.js) | `rateLimiter()` | Function body is `next()` only — no throttling implemented |
| [config/settings.js](config/settings.js) | `rateLimit.enabled` | Set to `false` globally |

---

### 17. Insecure File Upload

**Severity:** High

Uploaded files are stored with their original filenames and no content-type or extension validation.

| File | Location | Description |
|---|---|---|
| [src/app.js](src/app.js) | `multer` config | `filename` set to `file.originalname` — no sanitization |
| [src/app.js](src/app.js) | `/upload` route | No file type, extension, or size validation |

---

### 18. Miscellaneous

| Vulnerability | File | Description |
|---|---|---|
| Debug mode in production | [scripts/api_server.py](scripts/api_server.py) | `app.run(debug=True, host='0.0.0.0')` — exposes Werkzeug debugger publicly |
| Wildcard DB grants | [scripts/setup_db.sql](scripts/setup_db.sql) | `GRANT ALL PRIVILEGES ON *.* ... WITH GRANT OPTION` |
| `multipleStatements` enabled | [src/db.js](src/db.js) | MySQL pool allows stacked queries, worsening SQL injection impact |
| Credentials in shell history | [scripts/cron_jobs.sh](scripts/cron_jobs.sh) | `mysqldump -u$DB_USER -p$DB_PASS` exposes password in process list |
| Insecure `sshpass` usage | [scripts/cron_jobs.sh](scripts/cron_jobs.sh) | SSH password passed via command-line argument |
| World-writable paths | [scripts/cron_jobs.sh](scripts/cron_jobs.sh) | `chmod 777 $REPORT_DIR` on report output directory |
| Log file world-writable | [scripts/cron_jobs.sh](scripts/cron_jobs.sh) | `chmod 666` on rotated log file |
| Tokens in URL query params | [src/middleware.js](src/middleware.js) | Auth token accepted from `req.query.token` — logged in server access logs |
| Tokens in URL query params | [public/admin.js](public/admin.js) | `exportData()` appends token to URL query string |
| No `httpOnly` on session cookie | [src/app.js](src/app.js) | `httpOnly: false` makes session cookie accessible to JavaScript |
| No `secure` on session cookie | [src/app.js](src/app.js) | `secure: false` allows session cookie over plain HTTP |
| Auth state in `localStorage` | [public/admin.js](public/admin.js) | `auth_token` and `user_role` stored in `localStorage` — accessible to XSS |
| TLS verification disabled | [src/payments.js](src/payments.js) | `rejectUnauthorized: false` on HTTPS agent for payment API |

---

## Vulnerability Count by File

| File | Count |
|---|---|
| [src/app.js](src/app.js) | 18 |
| [scripts/api_server.py](scripts/api_server.py) | 16 |
| [src/db.js](src/db.js) | 6 |
| [scripts/data_processor.py](scripts/data_processor.py) | 12 |
| [scripts/cron_jobs.sh](scripts/cron_jobs.sh) | 9 |
| [src/auth.js](src/auth.js) | 8 |
| [src/payments.js](src/payments.js) | 7 |
| [src/websocket.js](src/websocket.js) | 7 |
| [src/fileManager.js](src/fileManager.js) | 7 |
| [public/index.html](public/index.html) | 6 |
| [public/admin.js](public/admin.js) | 7 |
| [scripts/generate_report.py](scripts/generate_report.py) | 7 |
| [config/settings.js](config/settings.js) | 4 |
| [src/middleware.js](src/middleware.js) | 5 |
| [admin/panel.html](admin/panel.html) | 2 |
| [scripts/setup_db.sql](scripts/setup_db.sql) | 4 |

---

## OWASP Top 10 (2021) Coverage

| OWASP Category | Covered |
|---|---|
| A01 — Broken Access Control | Yes |
| A02 — Cryptographic Failures | Yes |
| A03 — Injection | Yes |
| A04 — Insecure Design | Yes |
| A05 — Security Misconfiguration | Yes |
| A06 — Vulnerable and Outdated Components | Yes (`node-serialize` known RCE) |
| A07 — Identification and Authentication Failures | Yes |
| A08 — Software and Data Integrity Failures | Yes |
| A09 — Security Logging and Monitoring Failures | Yes |
| A10 — Server-Side Request Forgery | Yes |

---

> **Warning:** This codebase is for security tool evaluation only. Do not deploy it.
