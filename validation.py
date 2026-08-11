"""
validation.py
=============
Basic input validation for registration and login forms.

Validating input server-side (never trust client-side JS validation
alone) helps prevent malformed data, some injection attempts, and
weak passwords from ever reaching the database or hashing function.
"""

import re

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_username(username: str) -> tuple:
    """Only allow alphanumeric + underscore, 3-20 chars. Blocks obvious
    injection payloads (quotes, semicolons, SQL keywords) by restricting
    the character set entirely, rather than trying to blocklist patterns."""
    if not username:
        return False, "Username is required."
    if not USERNAME_REGEX.match(username):
        return False, "Username must be 3-20 characters (letters, numbers, underscore only)."
    return True, ""


def validate_email(email: str) -> tuple:
    if not email:
        return False, "Email is required."
    if not EMAIL_REGEX.match(email):
        return False, "Please enter a valid email address."
    return True, ""


def validate_password(password: str) -> tuple:
    """Enforce a reasonable minimum password strength policy."""
    if not password:
        return False, "Password is required."
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[^\w\s]", password):
        return False, "Password must contain at least one special character."
    return True, ""


def validate_registration(username: str, email: str, password: str, confirm_password: str) -> tuple:
    """Runs all registration validations. Returns (is_valid, error_message)."""
    ok, msg = validate_username(username)
    if not ok:
        return False, msg

    ok, msg = validate_email(email)
    if not ok:
        return False, msg

    ok, msg = validate_password(password)
    if not ok:
        return False, msg

    if password != confirm_password:
        return False, "Passwords do not match."

    return True, ""
