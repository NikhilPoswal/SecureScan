"""
auth.py — SecureScan Authentication Helpers
=============================================
Password hashing, user CRUD, and CSRF token utilities.

Password hashing:
  Uses Python stdlib hashlib.pbkdf2_hmac (SHA-256, 390,000 iterations).
  OWASP recommendation as of 2023 is 600,000 iterations for PBKDF2-HMAC-SHA256.
  We use 390,000 to stay well inside Vercel's 30s serverless timeout while
  remaining NIST-compliant. No extra dep (bcrypt) is needed.

  Stored hash format: "<hex_salt>:<hex_dk>" — both halves are hex-encoded
  so the entire value is a plain ASCII string safe to store in TEXT columns.

CSRF protection:
  Double-submit cookie pattern, session-bound:
    1. generate_csrf_token() stores a random token in session['csrf_token']
       and also returns it so the template can embed it in a hidden field.
    2. validate_csrf_token() compares the form value against the session value
       using hmac.compare_digest (constant-time, timing-attack resistant).
"""

from __future__ import annotations

import os
import hmac
import hashlib
import secrets
from typing import Optional, Dict, Any

import psycopg2

from db import get_db_connection


# ─── Password hashing ─────────────────────────────────────────────────────────

_PBKDF2_ITERATIONS = 390_000
_PBKDF2_ALGO = "sha256"
_SALT_BYTES = 32  # 256-bit salt
_DK_BYTES = 32    # 256-bit derived key


def hash_password(plain: str) -> str:
    """
    Hash a plain-text password and return a storable string.

    Returns a string in the form "<hex_salt>:<hex_dk>".
    """
    salt = os.urandom(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(_PBKDF2_ALGO, plain.encode("utf-8"), salt, _PBKDF2_ITERATIONS, dklen=_DK_BYTES)
    return salt.hex() + ":" + dk.hex()


def check_password(plain: str, stored_hash: str) -> bool:
    """
    Verify a plain-text password against a stored hash.
    Constant-time comparison to resist timing attacks.

    Returns True if the password matches, False otherwise.
    Returns False (never raises) on malformed stored_hash.
    """
    try:
        salt_hex, dk_hex = stored_hash.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected_dk = bytes.fromhex(dk_hex)
    except (ValueError, AttributeError):
        return False

    actual_dk = hashlib.pbkdf2_hmac(
        _PBKDF2_ALGO,
        plain.encode("utf-8"),
        salt,
        _PBKDF2_ITERATIONS,
        dklen=_DK_BYTES,
    )
    return hmac.compare_digest(actual_dk, expected_dk)


# ─── User CRUD ────────────────────────────────────────────────────────────────

def create_user(email: str, password: str) -> dict:
    """
    Insert a new user row and return the created user dict.

    Args:
        email:    User's email address (lowercased + stripped before insert).
        password: Plain-text password; hashed before storage.

    Returns:
        dict with keys: id, email, created_at

    Raises:
        ValueError — if the email is already registered.
        psycopg2.Error — on unexpected DB errors.
    """
    email = email.strip().lower()
    password_hash = hash_password(password)

    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor() as cur:
                try:
                    cur.execute(
                        """
                        INSERT INTO users (email, password_hash)
                        VALUES (%s, %s)
                        RETURNING id, email, created_at
                        """,
                        (email, password_hash),
                    )
                    row = cur.fetchone()
                    return dict(row)
                except psycopg2.errors.UniqueViolation:
                    raise ValueError(f"An account with this email already exists.")
    finally:
        conn.close()


def get_user_by_email(email: str) -> Optional[dict]:
    """
    Fetch a user row by email address.

    Returns a dict (id, email, password_hash, created_at) or None if not found.
    """
    email = email.strip().lower()
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, email, password_hash, created_at FROM users WHERE email = %s",
                (email,),
            )
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> Optional[dict]:
    """
    Fetch a user row by primary key.

    Returns a dict (id, email, created_at) or None if not found.
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, email, created_at FROM users WHERE id = %s",
                (user_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        conn.close()


# ─── CSRF helpers ─────────────────────────────────────────────────────────────

def generate_csrf_token(session: dict) -> str:
    """
    Generate a cryptographically random CSRF token, store it in the Flask
    session, and return it (so the template can embed it in a hidden field).

    Only generates a new token if one is not already in the session.
    """
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf_token(session: dict, form_value: str | None) -> bool:
    """
    Compare the submitted form CSRF token against the session-stored one.
    Uses constant-time comparison to prevent timing attacks.

    Returns True if valid, False if missing or mismatched.
    """
    expected = session.get("csrf_token")
    if not expected or not form_value:
        return False
    return hmac.compare_digest(expected, form_value)
