import sqlite3
import json
from typing import List, Optional
from pathlib import Path
from honeygrid.config import settings
from honeygrid.models import Token, IncidentEvent

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(settings.HONEYGRID_DB_PATH)
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
        raw_headers TEXT,
        mitre_technique TEXT,
        FOREIGN KEY(token_id) REFERENCES tokens(id)
    )
    """)
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
            geo_lat, geo_lon, raw_headers, mitre_technique
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        json.dumps(event.raw_headers) if event.raw_headers else None,
        event.mitre_technique
    ))
    incident_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return incident_id

def list_incidents(limit: int = 50) -> List[IncidentEvent]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    results = []
    for row in rows:
        results.append(IncidentEvent(
            id=row["id"],
            token_id=row["token_id"],
            timestamp=row["timestamp"],
            attacker_ip=row["attacker_ip"],
            is_local_ip=bool(row["is_local_ip"]),
            client_tool=row["client_tool"],
            user_agent=row["user_agent"],
            http_method=row["http_method"],
            request_path=row["request_path"],
            query_params=row["query_params"],
            geo_country=row["geo_country"],
            geo_city=row["geo_city"],
            geo_region=row["geo_region"],
            geo_isp=row["geo_isp"],
            geo_asn=row["geo_asn"],
            geo_lat=row["geo_lat"],
            geo_lon=row["geo_lon"],
            raw_headers=json.loads(row["raw_headers"] or "{}") if row["raw_headers"] else None,
            mitre_technique=row["mitre_technique"] or "T1552: Unsecured Credentials"
        ))
    return results
