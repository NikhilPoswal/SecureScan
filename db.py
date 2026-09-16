"""
db.py — SecureScan Database Layer
==================================
Thin wrapper around psycopg2 for Neon Postgres.

Connection strategy (serverless-safe):
  - Each request opens a fresh connection and closes it when done.
  - Neon's free tier enforces a connection limit (~100 concurrent).
    Opening/closing per-request is the correct pattern for Vercel
    serverless functions; connection pooling (PgBouncer etc.) is a
    Batch 2+ concern if connection churn ever becomes a bottleneck.

Environment variable:
  DATABASE_URL — full Postgres connection string (must include ?sslmode=require)
  e.g. postgresql://user:pass@ep-xxx.region.aws.neon.tech/dbname?sslmode=require

  Loaded from .env locally via python-dotenv.
  Injected by Vercel dashboard in production (no .env file is deployed).
"""

from __future__ import annotations

import os
import json
from typing import Optional, List, Tuple, Dict, Any

import psycopg2
import psycopg2.extras

# Load .env in local development.
# In Vercel production this is a no-op (dotenv won't find a .env file).
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed in some minimal environments


def get_db_connection() -> psycopg2.extensions.connection:
    """
    Open and return a new psycopg2 connection using DATABASE_URL.
    Caller is responsible for closing the connection (use in a try/finally
    or `with` block in route handlers).

    Raises:
        RuntimeError  — if DATABASE_URL is not set in the environment.
        psycopg2.Error — if the connection attempt fails.
    """
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        raise RuntimeError(
            "DATABASE_URL is not set. "
            "Add it to your .env file (local dev) or to Vercel environment "
            "variables (production). See .env.example for the format."
        )
    conn = psycopg2.connect(db_url, cursor_factory=psycopg2.extras.RealDictCursor, connect_timeout=10)
    return conn


# ─── Schema initialisation ────────────────────────────────────────────────────
# DDL is idempotent (IF NOT EXISTS) so it's safe to call on every cold start.
# In a warm Vercel container _DB_INITIALISED stays True, so the overhead is
# a single boolean check per invocation after the first.

_DB_INITIALISED = False


def init_db() -> None:
    """
    Create `users` and `scans` tables if they do not already exist.
    Safe to call multiple times — uses CREATE TABLE IF NOT EXISTS.
    """
    global _DB_INITIALISED
    if _DB_INITIALISED:
        return

    ddl = """
    CREATE TABLE IF NOT EXISTS users (
        id            SERIAL       PRIMARY KEY,
        email         TEXT         NOT NULL UNIQUE,
        password_hash TEXT         NOT NULL,
        created_at    TIMESTAMPTZ  DEFAULT NOW()
    );

    -- Index on email for O(log n) login lookups
    CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

    CREATE TABLE IF NOT EXISTS scans (
        id           SERIAL       PRIMARY KEY,
        user_id      INTEGER      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        url          TEXT         NOT NULL,
        final_url    TEXT         NOT NULL,
        score        INTEGER      NOT NULL,
        grade        VARCHAR(2)   NOT NULL,
        results_json JSONB        NOT NULL,
        created_at   TIMESTAMPTZ  DEFAULT NOW()
    );

    -- Index for fast user dashboard lookups sorted by date
    CREATE INDEX IF NOT EXISTS idx_scans_user_created ON scans (user_id, created_at DESC);
    """

    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(ddl)
    finally:
        conn.close()

    _DB_INITIALISED = True


# ─── Scan CRUD Operations (Batch 2) ──────────────────────────────────────────

def save_scan(user_id: int, url: str, final_url: str, score: int, grade: str, results_data: dict) -> int:
    """
    Save a scan result for a logged-in user.
    Returns the newly created scan ID.
    """
    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO scans (user_id, url, final_url, score, grade, results_json)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (user_id, url, final_url, score, grade, json.dumps(results_data)),
                )
                row = cur.fetchone()
                return row["id"]
    finally:
        conn.close()


def get_user_scans(user_id: int, limit: int = 20, offset: int = 0) -> Tuple[List[dict], int]:
    """
    Fetch a page of saved scans for the given user, ordered newest first.
    Returns (scans_list, total_count).
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS total FROM scans WHERE user_id = %s", (user_id,))
            total = cur.fetchone()["total"]

            cur.execute(
                """
                SELECT id, user_id, url, final_url, score, grade, created_at
                FROM scans
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
                """,
                (user_id, limit, offset),
            )
            rows = [dict(r) for r in cur.fetchall()]
            return rows, total
    finally:
        conn.close()


def get_scan_by_id(scan_id: int, user_id: int) -> Optional[dict]:
    """
    Fetch a specific scan by ID, strictly scoped to user_id.
    Returns None if not found or if the scan belongs to another user.
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, user_id, url, final_url, score, grade, results_json, created_at
                FROM scans
                WHERE id = %s AND user_id = %s
                """,
                (scan_id, user_id),
            )
            row = cur.fetchone()
            if not row:
                return None
            res = dict(row)
            if isinstance(res.get("results_json"), str):
                res["results_json"] = json.loads(res["results_json"])
            return res
    finally:
        conn.close()


def delete_scan(scan_id: int, user_id: int) -> bool:
    """
    Delete a specific scan by ID, strictly scoped to user_id.
    Returns True if a row was deleted, False otherwise.
    """
    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM scans WHERE id = %s AND user_id = %s",
                    (scan_id, user_id),
                )
                return cur.rowcount > 0
    finally:
        conn.close()

