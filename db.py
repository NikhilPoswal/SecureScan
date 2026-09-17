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

    CREATE TABLE IF NOT EXISTS monitored_sites (
        id               SERIAL       PRIMARY KEY,
        user_id          INTEGER      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        url              TEXT         NOT NULL,
        is_active        BOOLEAN      NOT NULL DEFAULT TRUE,
        check_frequency  VARCHAR(20)  NOT NULL DEFAULT 'daily',
        last_checked_at  TIMESTAMPTZ,
        created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        CONSTRAINT uq_user_monitored_url UNIQUE (user_id, url)
    );

    CREATE INDEX IF NOT EXISTS idx_monitored_sites_active_due ON monitored_sites (is_active, last_checked_at);
    CREATE INDEX IF NOT EXISTS idx_monitored_sites_user ON monitored_sites (user_id);
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


# ─── Monitored Sites CRUD & Operations (Batch 3) ──────────────────────────────

MAX_MONITORED_SITES_PER_USER = 3


def add_monitored_site(user_id: int, url: str, check_frequency: str = "daily") -> dict:
    """
    Add or reactivate a monitored site for a user.
    Enforces MAX_MONITORED_SITES_PER_USER (cap of 3 for free accounts).
    Raises ValueError if limit is reached or URL is invalid.
    Returns the monitored site record dict.
    """
    url = url.strip()
    if not url:
        raise ValueError("Please provide a valid URL to monitor.")

    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor() as cur:
                # Check if site is already actively monitored by this user
                cur.execute(
                    "SELECT id, is_active FROM monitored_sites WHERE user_id = %s AND url = %s",
                    (user_id, url),
                )
                existing = cur.fetchone()
                if existing and existing["is_active"]:
                    return dict(existing)

                # Check quota for active monitored sites
                cur.execute(
                    "SELECT COUNT(*) AS active_count FROM monitored_sites WHERE user_id = %s AND is_active = TRUE",
                    (user_id,),
                )
                count = cur.fetchone()["active_count"]
                if count >= MAX_MONITORED_SITES_PER_USER:
                    raise ValueError(
                        f"You have reached your {MAX_MONITORED_SITES_PER_USER}-site monitoring limit on the Free plan. "
                        "Remove a monitored site or upgrade to add more."
                    )

                # Upsert
                cur.execute(
                    """
                    INSERT INTO monitored_sites (user_id, url, is_active, check_frequency)
                    VALUES (%s, %s, TRUE, %s)
                    ON CONFLICT (user_id, url) DO UPDATE
                    SET is_active = TRUE, check_frequency = EXCLUDED.check_frequency
                    RETURNING id, user_id, url, is_active, check_frequency, last_checked_at, created_at
                    """,
                    (user_id, url, check_frequency),
                )
                return dict(cur.fetchone())
    finally:
        conn.close()


def stop_monitored_site(site_id: int, user_id: int) -> bool:
    """
    Stop monitoring a site (delete), strictly scoped to user_id.
    Returns True if removed, False otherwise.
    """
    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM monitored_sites WHERE id = %s AND user_id = %s",
                    (site_id, user_id),
                )
                return cur.rowcount > 0
    finally:
        conn.close()


def is_site_monitored(user_id: int, url: str) -> Tuple[bool, Optional[int]]:
    """
    Check if a specific URL is actively monitored by user_id.
    Returns (is_monitored, site_id).
    """
    url = url.strip()
    if not url:
        return False, None
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM monitored_sites WHERE user_id = %s AND url = %s AND is_active = TRUE",
                (user_id, url),
            )
            row = cur.fetchone()
            if row:
                return True, row["id"]
            return False, None
    finally:
        conn.close()


def count_user_monitored_sites(user_id: int) -> int:
    """
    Return count of actively monitored sites for user_id.
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS total FROM monitored_sites WHERE user_id = %s AND is_active = TRUE",
                (user_id,),
            )
            return cur.fetchone()["total"]
    finally:
        conn.close()


def get_user_monitored_sites(user_id: int) -> List[dict]:
    """
    Fetch all actively monitored sites for user_id, ordered newest first.
    Enriches each site with:
      - latest_score: score of the most recent scan for this url/user
      - latest_grade: grade of the most recent scan
      - latest_scan_id: scan ID of the most recent scan
      - recent_scores: list of recent scores/dates (up to 7) for trend indicator
      - trend_diff: difference between latest and oldest recent score
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, user_id, url, is_active, check_frequency, last_checked_at, created_at
                FROM monitored_sites
                WHERE user_id = %s AND is_active = TRUE
                ORDER BY created_at DESC
                """,
                (user_id,),
            )
            sites = [dict(r) for r in cur.fetchall()]

            for site in sites:
                cur.execute(
                    """
                    SELECT id, score, grade, created_at
                    FROM scans
                    WHERE user_id = %s AND (url = %s OR final_url LIKE %s)
                    ORDER BY created_at DESC
                    LIMIT 7
                    """,
                    (user_id, site["url"], f"%{site['url']}%"),
                )
                scans = [dict(s) for s in cur.fetchall()]
                if scans:
                    site["latest_score"] = scans[0]["score"]
                    site["latest_grade"] = scans[0]["grade"]
                    site["latest_scan_id"] = scans[0]["id"]
                    # Chronological order: oldest to newest
                    site["recent_scores"] = list(reversed(scans))
                    if len(scans) > 1:
                        site["trend_diff"] = scans[0]["score"] - scans[-1]["score"]
                    else:
                        site["trend_diff"] = 0
                else:
                    site["latest_score"] = None
                    site["latest_grade"] = None
                    site["latest_scan_id"] = None
                    site["recent_scores"] = []
                    site["trend_diff"] = 0

            return sites
    finally:
        conn.close()


def get_monitored_sites_due(limit: int = 15) -> List[dict]:
    """
    Fetch active monitored sites due for a check.
    A site is due if last_checked_at IS NULL or older than 20 hours.
    Limit avoids exceeding serverless timeout limits.
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, user_id, url, check_frequency, last_checked_at
                FROM monitored_sites
                WHERE is_active = TRUE
                  AND (last_checked_at IS NULL OR last_checked_at <= NOW() - INTERVAL '20 hours')
                ORDER BY last_checked_at ASC NULLS FIRST
                LIMIT %s
                """,
                (limit,),
            )
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def update_monitored_site_checked(site_id: int) -> None:
    """
    Update last_checked_at = NOW() for a monitored site.
    """
    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE monitored_sites SET last_checked_at = NOW() WHERE id = %s",
                    (site_id,),
                )
    finally:
        conn.close()


