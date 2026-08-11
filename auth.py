"""
auth.py
=======
Password hashing helpers using bcrypt.

WHY BCRYPT?
bcrypt automatically generates and stores a random salt with every hash,
and its "work factor" makes brute-forcing deliberately slow (unlike a
single fast hash like MD5/SHA-256, which is unsuitable for passwords).
This directly satisfies the task requirement: "hashed passwords (bcrypt
or Argon2)".

A safe fallback to Werkzeug's own salted hashing (scrypt) is included
only so this project can still run in environments where the bcrypt
package isn't installed (e.g. no internet access). On your machine,
run `pip install bcrypt` and it will be used automatically — bcrypt is
the intended/primary implementation for this project.
"""

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    from werkzeug.security import generate_password_hash, check_password_hash


def hash_password(plain_password: str) -> str:
    if BCRYPT_AVAILABLE:
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
        return hashed.decode("utf-8")
    else:
        # Fallback only — see module docstring. Uses scrypt under the hood.
        return "werkzeug$" + generate_password_hash(plain_password, method="scrypt")


def verify_password(plain_password: str, stored_hash: str) -> bool:
    if stored_hash.startswith("werkzeug$"):
        from werkzeug.security import check_password_hash
        return check_password_hash(stored_hash[len("werkzeug$"):], plain_password)

    if BCRYPT_AVAILABLE:
        try:
            return bcrypt.checkpw(plain_password.encode("utf-8"), stored_hash.encode("utf-8"))
        except ValueError:
            return False

    return False
