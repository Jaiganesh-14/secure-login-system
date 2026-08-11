# Secure Login System

A secure user authentication web app built with **Flask**, featuring bcrypt password hashing, SQL injection protection, session management, and optional two-factor authentication (2FA). Built as part of the Thiranex Cyber Security Virtual Internship to explore practical authentication security.

## Features

- **User Registration & Login** — with bcrypt-hashed passwords (12 salt rounds)
- **SQL Injection Protection** — every database query uses parameterized queries (see `database.py`)
- **Input Validation** — username, email, and password strength checks enforced server-side
- **Session Management** — signed, `httponly`, `SameSite=Lax` cookies with a 30-minute timeout, plus a working logout that fully clears the session
- **Account Lockout** — accounts lock for 15 minutes after 5 failed login attempts (basic brute-force protection)
- **Optional Two-Factor Authentication (2FA)** — TOTP-based, compatible with Google Authenticator / Authy, with QR code setup

## Project Structure

```
secure_login_system/
├── app.py              # Main Flask app and routes
├── auth.py             # bcrypt password hashing
├── database.py         # SQLite access (parameterized queries only)
├── validation.py        # Input validation rules
├── requirements.txt     # Dependencies
├── templates/            # HTML pages
│   ├── base.html
│   ├── register.html
│   ├── login.html
│   ├── dashboard.html
│   ├── 2fa_setup.html
│   └── 2fa_verify.html
└── static/
    └── style.css         # Styling
```

## How to Run

```bash
pip install -r requirements.txt
python3 app.py
```

Then open **http://localhost:5000** in your browser.

The SQLite database (`users.db`) is created automatically on first run.

## Security Notes

- **Password hashing**: Uses `bcrypt` with a 12-round salt. If `bcrypt` isn't installed, the app falls back to Werkzeug's `scrypt`-based hashing so it still runs — but bcrypt is the intended implementation for this project (install it via `requirements.txt`).
- **SQL injection**: All queries use `?` placeholders (parameterized queries) — user input is never concatenated directly into SQL strings.
- **Session cookies**: Configured with `HttpOnly` (blocks JavaScript access, mitigating XSS-based cookie theft) and `SameSite=Lax` (mitigates CSRF). In production behind HTTPS, also enable `SESSION_COOKIE_SECURE = True`.
- **Generic login errors**: The app shows "Invalid username or password" regardless of which part was wrong, to avoid revealing whether a username exists (prevents user enumeration).
- **2FA**: Requires `pyotp` and `qrcode[pil]`. If not installed, the app still runs — the 2FA option is just hidden.

## Tech Stack

- Python 3, Flask
- bcrypt (password hashing)
- SQLite (via `sqlite3`, no ORM — parameterized queries directly)
- pyotp + qrcode (TOTP 2FA)

## Learning Outcomes

This project helped build a practical understanding of:
- Why plain-text or weakly hashed passwords (MD5/SHA-256 alone) are unsafe, and how bcrypt's salting + work factor defends against brute-force attacks
- How SQL injection works and why parameterized queries prevent it
- Secure session cookie configuration (`HttpOnly`, `SameSite`, expiry)
- How TOTP-based 2FA works end-to-end (secret generation, QR provisioning, code verification)
- Basic brute-force mitigation via account lockout
