"""
app.py
======
Secure Login System — main Flask application.

Security features implemented:
  1. Password hashing with bcrypt (see auth.py)
  2. SQL injection protection via parameterized queries (see database.py)
  3. Server-side input validation (see validation.py)
  4. Session management using Flask's signed, httponly session cookies + logout
  5. Basic brute-force protection (account lockout after repeated failed logins)
  6. Optional TOTP-based Two-Factor Authentication (pyotp + QR code)

Author: <your name here>
Project: Thiranex Cyber Security Virtual Internship
"""

import io
import base64
import secrets
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)

import database as db
from auth import hash_password, verify_password
from validation import validate_registration, validate_username

try:
    import pyotp
    import qrcode
    TWOFA_AVAILABLE = True
except ImportError:
    TWOFA_AVAILABLE = False


app = Flask(__name__)

# SECRET_KEY signs the session cookie so it can't be tampered with client-side.
# In production, load this from an environment variable — never hardcode it.
app.config["SECRET_KEY"] = secrets.token_hex(32)

# Session cookie hardening
app.config["SESSION_COOKIE_HTTPONLY"] = True   # JS can't read the cookie (mitigates XSS theft)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # mitigates CSRF from cross-site requests
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
# In production behind HTTPS, also set: app.config["SESSION_COOKIE_SECURE"] = True

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------

def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def is_account_locked(user) -> bool:
    if not user["locked_until"]:
        return False
    locked_until = datetime.fromisoformat(user["locked_until"])
    return datetime.now() < locked_until


# ---------------------------------------------------------------
# Routes: Registration
# ---------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        is_valid, error = validate_registration(username, email, password, confirm_password)
        if not is_valid:
            flash(error, "error")
            return render_template("register.html")

        password_hash = hash_password(password)
        success = db.create_user(username, email, password_hash)

        if not success:
            flash("That username or email is already registered.", "error")
            return render_template("register.html")

        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# ---------------------------------------------------------------
# Routes: Login / Logout
# ---------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Validate the shape of the username before even hitting the DB.
        ok, _ = validate_username(username)
        user = db.get_user_by_username(username) if ok else None

        if user and is_account_locked(user):
            flash("Account temporarily locked due to repeated failed attempts. "
                  "Try again later.", "error")
            return render_template("login.html")

        if user and verify_password(password, user["password_hash"]):
            db.reset_failed_logins(username)

            if user["twofa_enabled"]:
                # Don't fully log in yet — require the TOTP code first.
                session["pending_2fa_user_id"] = user["id"]
                return redirect(url_for("verify_2fa"))

            _establish_session(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for("dashboard"))

        # Generic error message on purpose — doesn't reveal whether the
        # username exists or the password was wrong (prevents user enumeration).
        flash("Invalid username or password.", "error")

        if user:
            db.record_failed_login(username)
            updated_user = db.get_user_by_username(username)
            if updated_user["failed_login_attempts"] >= MAX_FAILED_ATTEMPTS:
                locked_until = (datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
                db.lock_account(username, locked_until)
                flash(f"Too many failed attempts. Account locked for {LOCKOUT_MINUTES} minutes.", "error")

    return render_template("login.html")


def _establish_session(user):
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# ---------------------------------------------------------------
# Routes: Dashboard (protected)
# ---------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    user = db.get_user_by_id(session["user_id"])
    return render_template("dashboard.html", user=user, twofa_available=TWOFA_AVAILABLE)


# ---------------------------------------------------------------
# Routes: Optional Two-Factor Authentication (TOTP)
# ---------------------------------------------------------------

@app.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    if not TWOFA_AVAILABLE:
        flash("2FA requires the 'pyotp' and 'qrcode' packages. Run: pip install pyotp qrcode[pil]", "error")
        return redirect(url_for("dashboard"))

    user = db.get_user_by_id(session["user_id"])

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        secret = session.get("pending_totp_secret")
        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            db.set_totp_secret(user["id"], secret)
            db.enable_2fa(user["id"])
            session.pop("pending_totp_secret", None)
            flash("Two-factor authentication enabled!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid code. Please try again.", "error")

    # Generate a new secret + QR code for setup
    secret = pyotp.random_base32()
    session["pending_totp_secret"] = secret
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=user["username"], issuer_name="Secure Login System")

    qr = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    qr_base64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return render_template("2fa_setup.html", qr_base64=qr_base64, secret=secret)


@app.route("/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    db.disable_2fa(session["user_id"])
    flash("Two-factor authentication disabled.", "success")
    return redirect(url_for("dashboard"))


@app.route("/2fa/verify", methods=["GET", "POST"])
def verify_2fa():
    pending_user_id = session.get("pending_2fa_user_id")
    if not pending_user_id:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        user = db.get_user_by_id(pending_user_id)
        totp = pyotp.TOTP(user["totp_secret"])

        if totp.verify(code):
            session.pop("pending_2fa_user_id", None)
            _establish_session(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid authentication code.", "error")

    return render_template("2fa_verify.html")


if __name__ == "__main__":
    db.init_db()
    app.run(debug=True, port=5000)
