import os
import time
import sqlite3
import json
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timezone, timedelta
from pathlib import Path
from honeygrid.config import settings
from honeygrid.models import Token, IncidentEvent, BrowserTelemetry, User
from honeygrid.core.auth import generate_session_token, generate_user_id

def get_db_path() -> str:
    """Returns database file path, auto-switching to /tmp if running in serverless environments like Vercel or on read-only filesystems."""
    if (
        os.environ.get("VERCEL")
        or os.environ.get("VERCEL_ENV")
        or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
        or os.environ.get("LAMBDA_TASK_ROOT")
    ):
        return "/tmp/honeygrid.db"
    
    # Try testing writability of configured path
    try:
        p = Path(settings.HONEYGRID_DB_PATH)
        p.parent.mkdir(parents=True, exist_ok=True)
        test_file = p.parent / ".perm_check"
        with open(test_file, "w") as f:
            f.write("1")
        test_file.unlink(missing_ok=True)
        return str(p)
    except Exception:
        return "/tmp/honeygrid.db"


def get_db_connection() -> sqlite3.Connection:
    db_path = get_db_path()
    # Ensure parent directory exists
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Table for registered users
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TEXT NOT NULL
    )
    """)

    # Table for user sessions
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        session_token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # Table for registered tokens
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tokens (
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
    )
    """)
    
    # Table for captured incident triggers
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        geo_lat REAL,
        geo_lon REAL,
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
        raw_headers TEXT,
        mitre_technique TEXT,
        FOREIGN KEY(token_id) REFERENCES tokens(id)
    )
    """)

    # Table for Operator Safe List (Allowlist)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS safe_ips (
        ip TEXT PRIMARY KEY,
        label TEXT NOT NULL,
        added_at TEXT NOT NULL,
        added_by TEXT NOT NULL
    )
    """)

    # Tables for Persistent Rate Limiting
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        attempt_time REAL NOT NULL
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time ON login_attempts(ip, attempt_time)")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS login_lockouts (
        ip TEXT PRIMARY KEY,
        locked_until REAL NOT NULL
    )
    """)

    # Table for Structured Security Audit Logs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        actor TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        outcome TEXT NOT NULL,
        metadata TEXT
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp)")
    
    # Migration helper for tokens: ensure owner_id and owner_email exist
    cursor.execute("PRAGMA table_info(tokens)")
    existing_token_cols = {row["name"] for row in cursor.fetchall()}
    for col_name, col_type in [("owner_id", "TEXT"), ("owner_email", "TEXT")]:
        if col_name not in existing_token_cols:
            try:
                cursor.execute(f"ALTER TABLE tokens ADD COLUMN {col_name} {col_type}")
            except sqlite3.OperationalError:
                pass

    # Migration helper for incidents: ensure hardware/threat cols exist
    cursor.execute("PRAGMA table_info(incidents)")
    existing_cols = {row["name"] for row in cursor.fetchall()}
    
    new_cols = [
        ("threat_score", "INTEGER DEFAULT 15"),
        ("connection_type", "TEXT DEFAULT 'Unknown'"),
        ("is_vpn_proxy", "INTEGER DEFAULT 0"),
        ("is_tor", "INTEGER DEFAULT 0"),
        ("gpu_renderer", "TEXT"),
        ("screen_res", "TEXT"),
        ("cpu_cores", "INTEGER"),
        ("device_memory", "INTEGER"),
        ("local_lan_ip", "TEXT"),
        ("client_timezone", "TEXT")
    ]
    for col_name, col_type in new_cols:
        if col_name not in existing_cols:
            try:
                cursor.execute(f"ALTER TABLE incidents ADD COLUMN {col_name} {col_type}")
            except sqlite3.OperationalError:
                pass

    conn.commit()
    conn.close()

# -------------------------------------------------------------
# User & Session Authentication Helpers
# -------------------------------------------------------------

def create_user(email: str, password_hash: str, salt: str, role: str = "user") -> User:
    conn = get_db_connection()
    cursor = conn.cursor()
    user_id = generate_user_id()
    now_iso = datetime.now(timezone.utc).isoformat()
    cursor.execute(
        "INSERT INTO users (id, email, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, email.strip().lower(), password_hash, salt, role, now_iso)
    )
    conn.commit()
    conn.close()
    return User(id=user_id, email=email.strip().lower(), role=role, created_at=now_iso)

def get_user_by_email(email: str) -> Optional[User]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, role, created_at FROM users WHERE LOWER(email) = LOWER(?)", (email.strip(),))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return User(id=row["id"], email=row["email"], role=row["role"], created_at=row["created_at"])

def get_user_auth_record_by_email(email: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, password_hash, salt, role, created_at FROM users WHERE LOWER(email) = LOWER(?)", (email.strip(),))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return dict(row)

def get_user_by_id(user_id: str) -> Optional[User]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, role, created_at FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return User(id=row["id"], email=row["email"], role=row["role"], created_at=row["created_at"])

def create_session(user_id: str, expire_hours: int = 168) -> str:
    conn = get_db_connection()
    cursor = conn.cursor()
    session_token = generate_session_token()
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(hours=expire_hours)).isoformat()
    cursor.execute(
        "INSERT INTO sessions (session_token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (session_token, user_id, now.isoformat(), expires_at)
    )
    conn.commit()
    conn.close()
    return session_token

def get_user_by_session(session_token: str) -> Optional[User]:
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
        SELECT users.id, users.email, users.role, users.created_at, sessions.expires_at
        FROM sessions
        JOIN users ON sessions.user_id = users.id
        WHERE sessions.session_token = ?
    """, (session_token,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None
    
    if row["expires_at"] < now_iso:
        cursor.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
        conn.commit()
        conn.close()
        return None
        
    conn.close()
    return User(id=row["id"], email=row["email"], role=row["role"], created_at=row["created_at"])

def delete_session(session_token: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
    conn.commit()
    conn.close()


# -------------------------------------------------------------
# Operator Safe List (Allowlist) Helpers
# -------------------------------------------------------------

def add_safe_ip(ip: str, label: str = "Authorized Operator Workstation", added_by: str = "admin") -> bool:
    clean_ip = ip.strip()
    if not clean_ip:
        return False
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
        INSERT OR REPLACE INTO safe_ips (ip, label, added_at, added_by)
        VALUES (?, ?, ?, ?)
    """, (clean_ip, label, now_iso, added_by))
    conn.commit()
    conn.close()
    return True

def remove_safe_ip(ip: str) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM safe_ips WHERE ip = ?", (ip.strip(),))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def list_safe_ips() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM safe_ips ORDER BY added_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def is_safe_ip(ip: str) -> bool:
    clean_ip = ip.strip()
    if not clean_ip:
        return False
    # 1. Check environment variable
    if settings.OPERATOR_SAFE_IPS:
        configured = [x.strip() for x in settings.OPERATOR_SAFE_IPS.split(",") if x.strip()]
        if clean_ip in configured:
            return True
    # 2. Check safe_ips table
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM safe_ips WHERE ip = ?", (clean_ip,))
    row = cursor.fetchone()
    conn.close()
    return row is not None


# -------------------------------------------------------------
# Persistent Rate Limiting Helpers
# -------------------------------------------------------------

def db_is_locked(ip: str, window_seconds: int = 600, max_attempts: int = 5, lockout_seconds: int = 600) -> Tuple[bool, int]:
    clean_ip = ip.strip()
    if not clean_ip:
        return False, 0
    now = time.time()
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Check active lockout
    cursor.execute("SELECT locked_until FROM login_lockouts WHERE ip = ?", (clean_ip,))
    row = cursor.fetchone()
    if row:
        locked_until = row[0]
        if now < locked_until:
            conn.close()
            return True, max(1, int(locked_until - now))
        else:
            cursor.execute("DELETE FROM login_lockouts WHERE ip = ?", (clean_ip,))
            conn.commit()

    # 2. Prune old attempts
    cutoff = now - window_seconds
    cursor.execute("DELETE FROM login_attempts WHERE attempt_time < ?", (cutoff,))
    
    # 3. Check attempt count
    cursor.execute("SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND attempt_time >= ?", (clean_ip, cutoff))
    count = cursor.fetchone()[0]
    if count >= max_attempts:
        locked_until = now + lockout_seconds
        cursor.execute("INSERT OR REPLACE INTO login_lockouts (ip, locked_until) VALUES (?, ?)", (clean_ip, locked_until))
        cursor.execute("DELETE FROM login_attempts WHERE ip = ?", (clean_ip,))
        conn.commit()
        conn.close()
        return True, lockout_seconds

    conn.commit()
    conn.close()
    return False, 0

def db_record_failure(ip: str, window_seconds: int = 600, max_attempts: int = 5, lockout_seconds: int = 600) -> int:
    clean_ip = ip.strip()
    if not clean_ip:
        return 0
    now = time.time()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("INSERT INTO login_attempts (ip, attempt_time) VALUES (?, ?)", (clean_ip, now))
    cutoff = now - window_seconds
    cursor.execute("DELETE FROM login_attempts WHERE attempt_time < ?", (cutoff,))
    cursor.execute("SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND attempt_time >= ?", (clean_ip, cutoff))
    count = cursor.fetchone()[0]

    if count >= max_attempts:
        locked_until = now + lockout_seconds
        cursor.execute("INSERT OR REPLACE INTO login_lockouts (ip, locked_until) VALUES (?, ?)", (clean_ip, locked_until))
        cursor.execute("DELETE FROM login_attempts WHERE ip = ?", (clean_ip,))
        conn.commit()
        conn.close()
        return max_attempts

    conn.commit()
    conn.close()
    return count

def db_record_success(ip: str):
    clean_ip = ip.strip()
    if not clean_ip:
        return
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM login_attempts WHERE ip = ?", (clean_ip,))
    cursor.execute("DELETE FROM login_lockouts WHERE ip = ?", (clean_ip,))
    conn.commit()
    conn.close()

# -------------------------------------------------------------
# Structured Security Audit Logging Helpers
# -------------------------------------------------------------

def record_audit_log(
    action: str,
    outcome: str,
    actor: str = "system",
    client_ip: str = "127.0.0.1",
    target: str = "",
    metadata: Optional[Dict[str, Any]] = None
) -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()
    meta_json = json.dumps(metadata or {})
    cursor.execute("""
        INSERT INTO audit_logs (timestamp, actor, client_ip, action, target, outcome, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (now_iso, actor, client_ip, action, target, outcome, meta_json))
    log_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return log_id

def list_audit_logs(limit: int = 50, action: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    if action:
        cursor.execute("SELECT * FROM audit_logs WHERE action = ? ORDER BY id DESC LIMIT ?", (action, limit))
    else:
        cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


# -------------------------------------------------------------
# Honeytoken & Incident Operations
# -------------------------------------------------------------

def save_token(token: Token) -> Token:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO tokens (id, token_type, label, description, created_at, trigger_count, is_active, metadata, owner_id, owner_email)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        token.id,
        token.token_type,
        token.label,
        token.description,
        token.created_at,
        token.trigger_count,
        1 if token.is_active else 0,
        json.dumps(token.metadata),
        token.owner_id,
        token.owner_email
    ))
    conn.commit()
    conn.close()
    return token

def get_token(token_id: str) -> Optional[Token]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tokens WHERE id = ?", (token_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    row_keys = row.keys()
    return Token(
        id=row["id"],
        token_type=row["token_type"],
        label=row["label"],
        description=row["description"],
        created_at=row["created_at"],
        trigger_count=row["trigger_count"],
        is_active=bool(row["is_active"]),
        owner_id=row["owner_id"] if "owner_id" in row_keys else None,
        owner_email=row["owner_email"] if "owner_email" in row_keys else None,
        metadata=json.loads(row["metadata"] or "{}")
    )

def list_tokens(user_id: Optional[str] = None, is_admin: bool = False) -> List[Token]:
    conn = get_db_connection()
    cursor = conn.cursor()
    if is_admin or user_id is None:
        cursor.execute("SELECT * FROM tokens ORDER BY created_at DESC")
    else:
        cursor.execute("SELECT * FROM tokens WHERE owner_id = ? ORDER BY created_at DESC", (user_id,))
    rows = cursor.fetchall()
    conn.close()
    results = []
    for row in rows:
        row_keys = row.keys()
        results.append(Token(
            id=row["id"],
            token_type=row["token_type"],
            label=row["label"],
            description=row["description"],
            created_at=row["created_at"],
            trigger_count=row["trigger_count"],
            is_active=bool(row["is_active"]),
            owner_id=row["owner_id"] if "owner_id" in row_keys else None,
            owner_email=row["owner_email"] if "owner_email" in row_keys else None,
            metadata=json.loads(row["metadata"] or "{}")
        ))
    return results

def record_incident(event: IncidentEvent) -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Update token trigger count
    cursor.execute("UPDATE tokens SET trigger_count = trigger_count + 1 WHERE id = ?", (event.token_id,))
    
    # Insert incident record
    cursor.execute("""
        INSERT INTO incidents (
            token_id, timestamp, attacker_ip, is_local_ip, client_tool,
            user_agent, http_method, request_path, query_params,
            geo_country, geo_city, geo_region, geo_isp, geo_asn,
            geo_lat, geo_lon, threat_score, connection_type, is_vpn_proxy,
            is_tor, gpu_renderer, screen_res, cpu_cores, device_memory,
            local_lan_ip, client_timezone, raw_headers, mitre_technique
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.token_id,
        event.timestamp,
        event.attacker_ip,
        1 if event.is_local_ip else 0,
        event.client_tool,
        event.user_agent,
        event.http_method,
        event.request_path,
        event.query_params,
        event.geo_country,
        event.geo_city,
        event.geo_region,
        event.geo_isp,
        event.geo_asn,
        event.geo_lat,
        event.geo_lon,
        event.threat_score,
        event.connection_type,
        1 if event.is_vpn_proxy else 0,
        1 if event.is_tor else 0,
        event.gpu_renderer,
        event.screen_res,
        event.cpu_cores,
        event.device_memory,
        event.local_lan_ip,
        event.client_timezone,
        json.dumps(event.raw_headers) if event.raw_headers else None,
        event.mitre_technique
    ))
    incident_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return incident_id

def update_incident_telemetry(token_id: str, telemetry: BrowserTelemetry):
    """Enriches the most recent incident for this token with browser/hardware telemetry."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE incidents 
        SET gpu_renderer = ?, screen_res = ?, cpu_cores = ?, device_memory = ?, local_lan_ip = ?, client_timezone = ?
        WHERE id = (SELECT MAX(id) FROM incidents WHERE token_id = ?)
    """, (
        telemetry.gpu_renderer,
        telemetry.screen_res,
        telemetry.cpu_cores,
        telemetry.device_memory,
        telemetry.local_lan_ip,
        telemetry.client_timezone,
        token_id
    ))
    conn.commit()
    conn.close()

def list_incidents(user_id: Optional[str] = None, is_admin: bool = False, limit: int = 50) -> List[IncidentEvent]:
    conn = get_db_connection()
    cursor = conn.cursor()
    if is_admin or user_id is None:
        cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,))
    else:
        cursor.execute("""
            SELECT incidents.* FROM incidents 
            JOIN tokens ON incidents.token_id = tokens.id 
            WHERE tokens.owner_id = ? 
            ORDER BY incidents.id DESC LIMIT ?
        """, (user_id, limit))
    rows = cursor.fetchall()
    conn.close()
    results = []
    for row in rows:
        row_dict = dict(row)
        lat = row_dict.get("geo_lat")
        lon = row_dict.get("geo_lon")
        country = row_dict.get("geo_country", "Unknown")
        city = row_dict.get("geo_city", "Unknown")
        is_local = bool(row_dict.get("is_local_ip", 0))

        # Self-healing coordinates for public IPs missing GPS fixes
        if (lat is None or lon is None) and not is_local:
            from honeygrid.core.geo import COUNTRY_CENTROIDS, extract_geo_from_headers
            raw_h_json = row_dict.get("raw_headers")
            if raw_h_json:
                try:
                    h_dict = json.loads(raw_h_json) if isinstance(raw_h_json, str) else raw_h_json
                    edge = extract_geo_from_headers(h_dict, row_dict.get("attacker_ip", ""))
                    if edge and edge.get("lat") and edge.get("lon"):
                        lat = edge["lat"]
                        lon = edge["lon"]
                        if country in ("Unknown", "Localhost / Internal Subnet"):
                            country = edge["country"]
                        if city in ("Unknown", "Private Network"):
                            city = edge["city"]
                except Exception:
                    pass

            if (lat is None or lon is None) and country and country != "Unknown":
                centroid = COUNTRY_CENTROIDS.get(country.upper())
                if centroid:
                    lat, lon = centroid

            if (lat is None or lon is None) and row_dict.get("attacker_ip", "").startswith("105.157."):
                lat, lon = 31.7917, -7.0926
                if country in ("Unknown", "Localhost / Internal Subnet"):
                    country = "Morocco"

        results.append(IncidentEvent(
            id=row_dict["id"],
            token_id=row_dict["token_id"],
            timestamp=row_dict["timestamp"],
            attacker_ip=row_dict["attacker_ip"],
            is_local_ip=is_local,
            client_tool=row_dict.get("client_tool", "Unknown"),
            user_agent=row_dict.get("user_agent"),
            http_method=row_dict.get("http_method"),
            request_path=row_dict.get("request_path"),
            query_params=row_dict.get("query_params"),
            geo_country=country,
            geo_city=city,
            geo_region=row_dict.get("geo_region", "Unknown"),
            geo_isp=row_dict.get("geo_isp", "Unknown"),
            geo_asn=row_dict.get("geo_asn", "Unknown"),
            geo_lat=lat,
            geo_lon=lon,
            threat_score=row_dict.get("threat_score", 15),
            connection_type=row_dict.get("connection_type", "Unknown"),
            is_vpn_proxy=bool(row_dict.get("is_vpn_proxy", 0)),
            is_tor=bool(row_dict.get("is_tor", 0)),
            gpu_renderer=row_dict.get("gpu_renderer"),
            screen_res=row_dict.get("screen_res"),
            cpu_cores=row_dict.get("cpu_cores"),
            device_memory=row_dict.get("device_memory"),
            local_lan_ip=row_dict.get("local_lan_ip"),
            client_timezone=row_dict.get("client_timezone"),
            raw_headers=json.loads(row_dict["raw_headers"] or "{}") if row_dict.get("raw_headers") else None,
            mitre_technique=row_dict.get("mitre_technique") or "T1552: Unsecured Credentials"
        ))
    return results

def get_dashboard_stats(user_id: Optional[str] = None, is_admin: bool = False) -> Dict[str, Any]:
    """Computes summary metrics for the SOC web dashboard, scoped by user unless admin."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if is_admin or user_id is None:
        cursor.execute("SELECT COUNT(*) FROM tokens")
        total_tokens = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM incidents")
        total_incidents = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE threat_score >= 50 OR is_vpn_proxy = 1")
        high_threat_incidents = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT attacker_ip) FROM incidents")
        unique_attackers = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT geo_country, COUNT(*) as count 
            FROM incidents 
            WHERE geo_country != 'Unknown' AND geo_country != 'Localhost / Internal Subnet'
            GROUP BY geo_country ORDER BY count DESC LIMIT 5
        """)
        top_countries = [{"country": r[0], "count": r[1]} for r in cursor.fetchall()]
    else:
        cursor.execute("SELECT COUNT(*) FROM tokens WHERE owner_id = ?", (user_id,))
        total_tokens = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM incidents JOIN tokens ON incidents.token_id = tokens.id WHERE tokens.owner_id = ?", (user_id,))
        total_incidents = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM incidents JOIN tokens ON incidents.token_id = tokens.id WHERE tokens.owner_id = ? AND (threat_score >= 50 OR is_vpn_proxy = 1)", (user_id,))
        high_threat_incidents = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT attacker_ip) FROM incidents JOIN tokens ON incidents.token_id = tokens.id WHERE tokens.owner_id = ?", (user_id,))
        unique_attackers = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT geo_country, COUNT(*) as count 
            FROM incidents 
            JOIN tokens ON incidents.token_id = tokens.id
            WHERE tokens.owner_id = ? AND geo_country != 'Unknown' AND geo_country != 'Localhost / Internal Subnet'
            GROUP BY geo_country ORDER BY count DESC LIMIT 5
        """, (user_id,))
        top_countries = [{"country": r[0], "count": r[1]} for r in cursor.fetchall()]
        
    conn.close()
    
    return {
        "total_tokens": total_tokens,
        "total_incidents": total_incidents,
        "high_threat_incidents": high_threat_incidents,
        "unique_attackers": unique_attackers,
        "top_countries": top_countries
    }
