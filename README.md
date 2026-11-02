# ☁️ Smart Cloud Data Protection System

A Zero Trust Architecture cloud file storage system built with **Flask**,
featuring Multi-Factor Authentication, Risk Based Authentication,
AES-256-GCM envelope encryption, encrypted file fragmentation, immutable
hash-chained audit logs, and AWS S3 storage.

---

## 🔐 Security Features

### 1. Registration with First-Time Email OTP Verification
- Register with **any email id** + a password
- A 6-digit **OTP is sent to the email** for first-time verification
- The account is only usable after the email is verified
- OTP expires after **5 minutes** (configurable)
- OTP stored only as a **SHA-256 hash** — never plaintext

```
Register (email + password) → OTP sent → Verify OTP → Account active
```

### 1b. Risk-Based Login
- **Low risk** (< 40) → password-only login
- **Medium risk** (40–79) → password **+ email OTP** verification
- **High risk** (≥ 80) → login **blocked**, account locked, alert sent

### 1c. Account Lock + Email Alert + OTP Unlock
The account is locked **and an alert email is sent** when:
- Password is entered wrong **≥ 5 times** (`MAX_FAILED_ATTEMPTS`),
  locking the account for **30 minutes** (`LOCK_DURATION_MINUTES`)
- The risk score reaches the **high threshold** (≥ 80)

To open the account again the user verifies the **unlock OTP** sent to
their email (10 minute validity). Unlocking resets failures and lowers risk.

### 2. IP Rate Limiting (Flask-Limiter)
| Endpoint   | Limit        |
|------------|--------------|
| `/login`   | 5 per minute |
| `/register`| 3 per minute |
| `/upload`  | 20 per minute|
| `/download`| 30 per minute|
| `/dashboard`| 60 per minute|

Exceeding a limit returns **HTTP 429**.

> **Note:** Without working AWS credentials the app automatically falls
> back to a local storage folder (`local_bucket/`) so the full demo
> works. Set `STORAGE_BACKEND=s3` to force real Amazon S3.

### 3. Risk Based Authentication
Risk scores accumulate from failed attempts (+20 each) and decay on
successful logins / OTP unlocks.

| Risk Level | Score   | Decision                             |
|------------|---------|--------------------------------------|
| Low        | < 40    | Allow Login (password only)          |
| Medium     | 40–79   | Password + Email OTP verification    |
| High       | ≥ 80    | Login blocked + locked + alert + OTP unlock |

When the risk score reaches the high threshold the login is blocked,
an alert email is sent, and the account can only be opened again via OTP.

### 3b. OTP Attempt & Resend Limits
- Login/register OTP expires after **5 minutes**
- Max **3 wrong OTP attempts** — after that a **new OTP** is issued and sent
- Max **3 manual resends** — the previous OTP is invalidated immediately
- OTPs are stored only as **SHA-256 hashes**, never plaintext

### 3c. Step-Up Authentication (Sensitive Operations)
Beyond login, the app now requires an **email OTP** for each sensitive
operation, issued on demand and valid for **5 minutes**:

| Operation        | Endpoint                                 | Page / redirect                              |
|------------------|------------------------------------------|----------------------------------------------|
| Download file    | `GET /download/<email>/<filename>`       | `/verify_stepup?intent=download`             |
| Delete file      | `POST /files/<id>/delete`                | `/verify_stepup?intent=delete`               |
| Change password  | `POST /change_password` → `POST /verify_password_otp` | `/verify_stepup?intent=password` |

- The OTP is **single-use** — a second attempt with the same OTP fails
- Each attempt/re-issue is logged and emailed
- Max **3 wrong OTP attempts** → a **new OTP** is issued and sent
- Max **3 manual resends** → 4th resend returns **429**
- **High risk (≥ 80)** blocks the operation outright, locks the account,
  sends a "High Risk Operation Blocked" alert, and writes a blocked audit entry
- After a successful password change **all active sessions are invalidated**
  (`auth_version` is bumped and stale sessions are cleared on next request)

### 4. SHA-256 Integrity Verification
- Upload: `file → SHA-256 → AES-256-GCM → HMAC → fragments → S3`
- The SHA-256 digest is stored in the database
- Download: `fragments → merge → HMAC verify → decrypt → SHA-256 verify`
- On mismatch the download is **blocked** and tampering is logged + emailed

### 5. Encrypted File Fragmentation
```
AES Encrypt → Split into N parts → Upload parts → Store metadata
Download → Retrieve parts → Merge → SHA-256 verify → Decrypt → Download
```
Fragment count and metadata are stored in the `File` table.

### 6. Immutable Hash-Chained Audit Logs
Every audit entry stores `previous_hash` + `current_hash`:

```
Log1 → Hash A → Log2(prev A) → Hash B → Log3(prev B) → Hash C
```

Each entry contains: previous hash, current hash, timestamp, user, IP,
device, action, status, risk. Modifying any entry breaks the whole chain.

### 7. Email Alerts (Gmail SMTP via App Password)
Professional HTML emails branded **"Smart Cloud Security"** are sent for:
- **Your Login OTP** — "Do not share this OTP", valid for 5 minutes
- **Account Locked** — after 5 failed attempts + unlock OTP
- **Account Unlock Verification** — unlock OTP, expires in 10 minutes
- **High Risk Login Attempt Detected** — Time / IP / Browser / OS / Location
- **New Device Login** — Device / Browser / OS / IP / Time
- **Multiple Failed Login Attempts**
- **Password Changed Successfully** — Time / IP
- **File Uploaded Successfully** — Filename / Upload Time
- **File Downloaded** — Filename / Time
- **File Integrity Alert** — tampering detected, download blocked

Emails are sent with **Gmail SMTP using an App Password** (no Google
OAuth). All settings come from `.env`. Without SMTP configured, messages
are logged to the console instead.

### 8. Security Headers
`Content-Security-Policy`, `Strict-Transport-Security`,
`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy`, `X-XSS-Protection`, `Permissions-Policy`.

### 9. Secure Cookies
- `SESSION_COOKIE_HTTPONLY = True`
- `SESSION_COOKIE_SAMESITE = "Strict"`
- `SESSION_COOKIE_SECURE = True` (behind HTTPS, `False` on localhost)

### 10. Admin Dashboard
- All users, all audit logs
- Risk scores & locked accounts
- **Unlock accounts**
- Search users & logs
- Recent logins / uploads / downloads

### 11. AWS Security
- All credentials moved to `.env` (git-ignored)
- No hardcoded keys anywhere in the code
- `.env.example` template provided

### 12. Encryption Improvements
- **Random AES-256 key per file**
- **Master key** wraps each file key (envelope encryption)
- **Key rotation ready** (versioned format + master key file)
- **HMAC-SHA256** integrity anchor over ciphertext
- Legacy files (old static-key format) remain decryptable

---

## 🗂 Project Structure

```
major-project/
├── app.py             # Application factory, blueprints, middleware
├── config.py          # Loads all settings from .env
├── models.py          # User, File, AuditLog + DB migration
├── auth.py            # Register / Login / OTP / Password
├── storage.py         # Upload / Download / File list
├── admin.py           # Admin dashboard, users, unlock, logs
├── security.py        # Rate limiter, risk engine, headers, OTP helpers
├── audit.py           # Hash-chained immutable audit logging
├── crypto.py          # AES-256-GCM envelope encryption + fragmentation
├── crypto_utils.py    # Backward-compatible wrapper
├── s3_manager.py      # AWS S3 client (credentials from .env)
├── email_service.py   # SMTP OTP + alerts
├── templates/         # HTML pages
├── static/style.css   # UI styles
├── requirements.txt
├── .env               # Secrets (never commit)
└── .env.example       # Template
```

---

## 🚀 Setup

### 1. Create the virtual environment (optional, if not present)
```bash
python -m venv venv
```

### 2. Install dependencies
```bash
venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

### 3. Configure `.env`
```bash
copy .env.example .env
```
Fill in:
- `SECRET_KEY` — `python -c "import secrets;print(secrets.token_hex(32))"`
- `MASTER_KEY` — `python -c "import secrets;print(secrets.token_hex(32))"`
- AWS S3 credentials and bucket name
- `STORAGE_BACKEND` — `auto` (S3 when keys+bucket set, else local),
  `s3` (always AWS), or `local` (demo mode: encrypted fragments stored
  in a local `local_bucket/` folder, no AWS needed)
- SMTP settings if you want real emails (`MAIL_ENABLED=true`)

> **Important:** If you leave `MASTER_KEY` empty, the system generates a
> key and stores it in `keys/master.key` automatically on first run.

### 4. Run
```bash
python app.py
```
Open http://localhost:5000

### 5. Promote a user to admin
```bash
flask --app app.py create-admin your@email.com
```
Users listed in `ADMIN_EMAILS` in `.env` are promoted automatically too.

### 6. Enable Login with Google (optional)
> This project now uses **email + password** with OTP for first-time
> verification and account unlocks. The Google OAuth option has been
> removed from the UI. If you previously added `GOOGLE_*` variables
> to `.env`, they are ignored and can be deleted.

---

## 📧 Email (MFA / Alerts)

Without SMTP configured, emails are logged to the console instead, so the
system works fully for demos. To send real emails, enable 2-Step
Verification on your Google account, generate an **App Password**
(see "App passwords" under Security — if only passkeys/authenticator show,
temporarily remove the passkey so App passwords appears), then set in `.env`:

```
MAIL_ENABLED=true
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=you@gmail.com
MAIL_PASSWORD=your-16-char-app-password
MAIL_FROM=you@gmail.com
ADMIN_EMAIL=you@gmail.com
```

> **Note:** This project uses Gmail SMTP only. Google OAuth ("Sign in
> with Google") is intentionally **not** used.

**Dev convenience:** with `DEV_MODE=true`, the current OTP is shown on the
`/verify_otp` page and available via `/dev/otp`. Disable `DEV_MODE` for
production.

---

## 🛠 Database Migration

The database upgrades **automatically on startup** — missing columns
(`otp`, `otp_expiry`, `otp_created_at`, `otp_attempts`, `otp_resends`,
`mfa_enabled`, `email_verified`, `last_login_ip`, `last_device`,
`is_admin`, `locked_until`, `unlock_otp`, `unlock_expiry`,
`download_otp_*`, `delete_otp_*`, `password_otp_*` (step-up OTP state),
`auth_version`, hash-chain
fields) are added and the audit chain is rebuilt. No manual SQL required.

---

## ⚠️ Security Notes

1. **Rotate your AWS keys.** The keys previously stored in `config.py`
   (now moved to `.env`) may have been committed to Git history. Create
   new IAM keys and update `.env`.
2. Keep `MASTER_KEY` and `SECRET_KEY` secret.
3. Set `COOKIE_SECURE=true` when deploying behind HTTPS.
4. The current CSP allows `'unsafe-inline'` for scripts/styles because the
   templates use inline handlers — for strict production hardening, move
   to external assets with nonce-based CSP.
5. Flask-Limiter uses in-memory storage by default (`memory://`) — use a
   shared backend (Redis) for multi-process deployments.

---

## 🧪 Tested Flow

- Register (email + password) → OTP sent → Verify → auto-login → Dashboard
- Logout → login with password only (low risk, no OTP)
- Medium risk (40–79) → password + OTP verification → dashboard
- 5 wrong passwords → alert email + account locked (30 min) → OTP unlock
- High risk score (≥ 80) → login blocked + alert + locked → OTP unlock
- 3 wrong OTP attempts → new OTP issued + sent automatically
- 3 resends max → 4th resend rejected (429)
- Download → OTP challenge (202) → verify OTP → byte-perfect download
- Download/delete/password OTP is single-use → reused OTP fails
- Delete → OTP challenge → verify → row + fragments removed + confirmation email
- Change password → OTP challenge → verify → session invalidated → new password required
- Upload → SHA-256 → encrypt → fragment → S3
- Download → merge → HMAC → decrypt → SHA-256 verify
- Tampered fragment → download blocked + logged + "File Integrity Alert"
- 6th login within a minute → HTTP 429
- Admin unlock, user search, log search
- Audit chain tampering → detected by `audit.verify_chain()`

---

## 📄 License

Academic / Final Year Major Project
