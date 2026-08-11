"""
database.py
============
Handles all database access for the Secure Login System.

SQL INJECTION PROTECTION:
Every single query in this file uses parameterized queries (the "?"
placeholders below), which means user input is NEVER concatenated
directly into a SQL string. sqlite3 handles escaping safely under the
hood. This is the #1 defense against SQL injection attacks.

NEVER do this (vulnerable to SQL injection):
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")

ALWAYS do this instead (safe):
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
"""

import sqlite3
from contextlib import contextmanager

DB_PATH = "users.db"


@contextmanager
def get_db():
    """Context manager that yields a connection and always closes it."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    """Create the users table if it doesn't already exist."""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT,
                twofa_enabled INTEGER DEFAULT 0,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


def create_user(username: str, email: str, password_hash: str) -> bool:
    """Insert a new user. Returns False if username/email already exists."""
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, password_hash),
            )
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def get_user_by_username(username: str):
    with get_db() as conn:
        cursor = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        )
        return cursor.fetchone()


def get_user_by_id(user_id: int):
    with get_db() as conn:
        cursor = conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        )
        return cursor.fetchone()


def set_totp_secret(user_id: int, secret: str):
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user_id)
        )
        conn.commit()


def enable_2fa(user_id: int):
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET twofa_enabled = 1 WHERE id = ?", (user_id,)
        )
        conn.commit()


def disable_2fa(user_id: int):
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET twofa_enabled = 0, totp_secret = NULL WHERE id = ?",
            (user_id,),
        )
        conn.commit()


def record_failed_login(username: str):
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 "
            "WHERE username = ?",
            (username,),
        )
        conn.commit()


def reset_failed_logins(username: str):
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL "
            "WHERE username = ?",
            (username,),
        )
        conn.commit()


def lock_account(username: str, locked_until_iso: str):
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET locked_until = ? WHERE username = ?",
            (locked_until_iso, username),
        )
        conn.commit()
