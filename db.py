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

import os
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
    conn = psycopg2.connect(db_url, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn


# ─── Schema initialisation ────────────────────────────────────────────────────
# DDL is idempotent (IF NOT EXISTS) so it's safe to call on every cold start.
# In a warm Vercel container _DB_INITIALISED stays True, so the overhead is
# a single boolean check per invocation after the first.

_DB_INITIALISED = False


def init_db() -> None:
    """
    Create the `users` table if it does not already exist.
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
    """

    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(ddl)
    finally:
        conn.close()

    _DB_INITIALISED = True
