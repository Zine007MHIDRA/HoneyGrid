import os
import sqlite3
import json
from typing import List, Optional, Dict, Any
from pathlib import Path
from honeygrid.config import settings
from honeygrid.models import Token, IncidentEvent, BrowserTelemetry

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
    
    # Migration helper: ensure new columns exist if table was previously created
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

def save_token(token: Token) -> Token:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO tokens (id, token_type, label, description, created_at, trigger_count, is_active, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        token.id,
        token.token_type,
        token.label,
        token.description,
        token.created_at,
        token.trigger_count,
        1 if token.is_active else 0,
        json.dumps(token.metadata)
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
    return Token(
        id=row["id"],
        token_type=row["token_type"],
        label=row["label"],
        description=row["description"],
        created_at=row["created_at"],
        trigger_count=row["trigger_count"],
        is_active=bool(row["is_active"]),
        metadata=json.loads(row["metadata"] or "{}")
    )

def list_tokens() -> List[Token]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tokens ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [
        Token(
            id=row["id"],
            token_type=row["token_type"],
            label=row["label"],
            description=row["description"],
            created_at=row["created_at"],
            trigger_count=row["trigger_count"],
            is_active=bool(row["is_active"]),
            metadata=json.loads(row["metadata"] or "{}")
        ) for row in rows
    ]

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

def list_incidents(limit: int = 50) -> List[IncidentEvent]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    results = []
    for row in rows:
        row_dict = dict(row)
        results.append(IncidentEvent(
            id=row_dict["id"],
            token_id=row_dict["token_id"],
            timestamp=row_dict["timestamp"],
            attacker_ip=row_dict["attacker_ip"],
            is_local_ip=bool(row_dict.get("is_local_ip", 0)),
            client_tool=row_dict.get("client_tool", "Unknown"),
            user_agent=row_dict.get("user_agent"),
            http_method=row_dict.get("http_method"),
            request_path=row_dict.get("request_path"),
            query_params=row_dict.get("query_params"),
            geo_country=row_dict.get("geo_country", "Unknown"),
            geo_city=row_dict.get("geo_city", "Unknown"),
            geo_region=row_dict.get("geo_region", "Unknown"),
            geo_isp=row_dict.get("geo_isp", "Unknown"),
            geo_asn=row_dict.get("geo_asn", "Unknown"),
            geo_lat=row_dict.get("geo_lat"),
            geo_lon=row_dict.get("geo_lon"),
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

def get_dashboard_stats() -> Dict[str, Any]:
    """Computes summary metrics for the SOC web dashboard."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
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
    
    conn.close()
    
    return {
        "total_tokens": total_tokens,
        "total_incidents": total_incidents,
        "high_threat_incidents": high_threat_incidents,
        "unique_attackers": unique_attackers,
        "top_countries": top_countries
    }
