"""
Database backend selection.

SQLite (default) keeps local development and tests zero-setup. When a Postgres connection string is
configured (DATABASE_URL, or POSTGRES_URL as set by Supabase's Vercel integration), every query in
honeygrid.database runs against Postgres instead, through a thin adapter that keeps the same
cursor API: "?" placeholders, row["col"] and row[0] access, fetchone/fetchall, rowcount.
"""
import os
import threading
from typing import Any, Dict, Optional, Sequence
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

# Query parameters libpq understands; integrations add others (e.g. Supabase's "supa=..."),
# which libpq would reject, so everything else is dropped.
_LIBPQ_PARAMS = {
    "sslmode", "sslrootcert", "sslcert", "sslkey", "connect_timeout", "application_name",
    "options", "target_session_attrs", "keepalives", "keepalives_idle",
}

def database_url() -> Optional[str]:
    if os.getenv("HONEYGRID_FORCE_SQLITE"):
        return None
    for key in ("DATABASE_URL", "POSTGRES_URL"):
        value = os.getenv(key, "").strip()
        if value.startswith(("postgres://", "postgresql://")):
            return _normalize_url(value)
    return None

def _normalize_url(url: str) -> str:
    parts = urlsplit(url)
    query = {k: v for k, v in parse_qsl(parts.query) if k in _LIBPQ_PARAMS}
    query.setdefault("sslmode", "require")
    query.setdefault("connect_timeout", "10")
    query.setdefault("application_name", "honeygrid")
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))

def is_postgres() -> bool:
    return database_url() is not None

def describe() -> str:
    """Backend summary safe to log (no credentials)."""
    url = database_url()
    if not url:
        return "sqlite"
    parts = urlsplit(url)
    return f"postgres://{parts.hostname}:{parts.port or 5432}{parts.path}"

# ---------------------------------------------------------------- Postgres adapter

class HybridRow(dict):
    """A dict row that also supports positional access, like sqlite3.Row."""
    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)

_SQL_CACHE: Dict[str, str] = {}

def translate(sql: str) -> str:
    """SQLite-flavoured SQL -> Postgres: %-escaping, ?-placeholders, case-insensitive LIKE."""
    cached = _SQL_CACHE.get(sql)
    if cached is None:
        cached = sql.replace("%", "%%").replace("?", "%s").replace(" LIKE ", " ILIKE ")
        _SQL_CACHE[sql] = cached
    return cached

class PgCursor:
    """Each statement borrows a pooled autocommit connection, reads all results, and returns it at
    once. No connection is ever held between statements, so an exception anywhere can't leak one,
    and the transaction pooler never sees a connection idling inside a transaction."""
    def __init__(self, pool):
        self._pool = pool
        self._rows = []
        self._rowcount = -1

    def execute(self, sql: str, params: Sequence[Any] = ()):
        import psycopg
        from psycopg.rows import dict_row
        query, args = translate(sql), tuple(params or ())  # a tuple even when empty, so %% is un-escaped
        for attempt in (1, 2):
            try:
                with self._pool.connection() as conn:
                    cur = conn.cursor(row_factory=dict_row)
                    cur.execute(query, args)
                    self._rows = [HybridRow(r) for r in cur.fetchall()] if cur.description else []
                    self._rowcount = cur.rowcount
                return self
            except psycopg.OperationalError:
                # The pooler occasionally drops an idle connection; the pool discards it, retry once
                if attempt == 2:
                    raise
        return self

    def fetchone(self):
        return self._rows.pop(0) if self._rows else None

    def fetchall(self):
        rows, self._rows = self._rows, []
        return rows

    @property
    def rowcount(self) -> int:
        return self._rowcount

class PgConnection:
    """Same surface as a sqlite3 connection. Statements autocommit, so commit/close are no-ops."""
    def __init__(self, pool):
        self._pool = pool

    def cursor(self) -> PgCursor:
        return PgCursor(self._pool)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass

_pool = None
_pool_lock = threading.Lock()

def get_pool():
    """One small pool per process. Serverless instances stay warm between requests, so reusing
    connections avoids a new TLS handshake to Supabase on every query."""
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                from psycopg_pool import ConnectionPool
                _pool = ConnectionPool(
                    database_url(),
                    min_size=0,
                    max_size=int(os.getenv("HONEYGRID_DB_POOL_SIZE", "4")),
                    # Supabase's transaction pooler can't keep prepared statements; statements autocommit
                    kwargs={"prepare_threshold": None, "autocommit": True},
                    timeout=15,
                    max_idle=120,
                    open=True,
                )
    return _pool

def pg_connection() -> PgConnection:
    return PgConnection(get_pool())

# Postgres schema: the final shape of the SQLite schema plus its migrations. Timestamps stay ISO-8601
# TEXT so comparisons behave identically on both backends. incidents.token_id has no foreign key
# because built-in scanner traps (e.g. /.env) record incidents without a tokens row.
PG_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TEXT NOT NULL,
        must_change_password INTEGER NOT NULL DEFAULT 0
    )""",
    """CREATE TABLE IF NOT EXISTS sessions (
        session_token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)",
    """CREATE TABLE IF NOT EXISTS tokens (
        id TEXT PRIMARY KEY,
        token_type TEXT NOT NULL,
        label TEXT NOT NULL,
        description TEXT,
        created_at TEXT NOT NULL,
        trigger_count INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        owner_id TEXT,
        owner_email TEXT,
        metadata TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_tokens_owner ON tokens(owner_id)",
    """CREATE TABLE IF NOT EXISTS incidents (
        id BIGSERIAL PRIMARY KEY,
        token_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        attacker_ip TEXT NOT NULL,
        is_local_ip INTEGER DEFAULT 0,
        client_tool TEXT,
        user_agent TEXT,
        http_method TEXT,
        request_path TEXT,
        query_params TEXT,
        geo_country TEXT,
        geo_city TEXT,
        geo_region TEXT,
        geo_isp TEXT,
        geo_asn TEXT,
        geo_lat DOUBLE PRECISION,
        geo_lon DOUBLE PRECISION,
        threat_score INTEGER DEFAULT 15,
        connection_type TEXT DEFAULT 'Unknown',
        is_vpn_proxy INTEGER DEFAULT 0,
        is_tor INTEGER DEFAULT 0,
        gpu_renderer TEXT,
        screen_res TEXT,
        cpu_cores INTEGER,
        device_memory INTEGER,
        local_lan_ip TEXT,
        client_timezone TEXT,
        client_platform TEXT,
        raw_headers TEXT,
        mitre_technique TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_incidents_ip ON incidents(attacker_ip)",
    "CREATE INDEX IF NOT EXISTS idx_incidents_token ON incidents(token_id)",
    """CREATE TABLE IF NOT EXISTS safe_ips (
        id BIGSERIAL PRIMARY KEY,
        ip TEXT NOT NULL,
        owner_id TEXT,
        label TEXT NOT NULL,
        added_at TEXT NOT NULL,
        added_by TEXT NOT NULL,
        UNIQUE(ip, owner_id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_safe_ips_ip ON safe_ips(ip)",
    """CREATE TABLE IF NOT EXISTS login_attempts (
        id BIGSERIAL PRIMARY KEY,
        ip TEXT NOT NULL,
        attempt_time DOUBLE PRECISION NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time ON login_attempts(ip, attempt_time)",
    """CREATE TABLE IF NOT EXISTS login_lockouts (
        ip TEXT PRIMARY KEY,
        locked_until DOUBLE PRECISION NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS audit_logs (
        id BIGSERIAL PRIMARY KEY,
        timestamp TEXT NOT NULL,
        actor TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        outcome TEXT NOT NULL,
        metadata TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp)",
    """CREATE TABLE IF NOT EXISTS pending_telemetry (
        id BIGSERIAL PRIMARY KEY,
        token_id TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        is_local INTEGER DEFAULT 0,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS password_resets (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0
    )""",
    """CREATE TABLE IF NOT EXISTS used_captchas (
        sig TEXT PRIMARY KEY,
        expires_at DOUBLE PRECISION NOT NULL
    )""",
]

# Supabase publishes every public-schema table through its REST API. Row-level security with no
# policies closes that door on every table (including ones added later), while HoneyGrid, which
# connects as the tables' owner, is unaffected. Idempotent, so it runs on every cold start.
PG_TABLES = ["users", "sessions", "tokens", "incidents", "safe_ips", "login_attempts",
             "login_lockouts", "audit_logs", "pending_telemetry", "password_resets", "used_captchas"]
PG_SCHEMA += [f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY" for t in PG_TABLES]
