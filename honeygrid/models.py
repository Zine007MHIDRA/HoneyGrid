from datetime import datetime, timezone
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

class TokenCreate(BaseModel):
    token_type: str = Field(..., description="Type of token: web, aws_key, db_conn, env_file, canary_pdf, honeyfile")
    label: str = Field(..., description="Identifying name e.g., 'Finance-Drive-Honeyfile'")
    description: Optional[str] = Field(None, description="Context on where this token is planted")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

class Token(BaseModel):
    id: str
    token_type: str
    label: str
    description: Optional[str] = None
    created_at: str
    trigger_count: int = 0
    is_active: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)

class IncidentEvent(BaseModel):
    id: Optional[int] = None
    token_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    attacker_ip: str
    is_local_ip: bool = False
    client_tool: str = "Unknown"
    user_agent: Optional[str] = None
    http_method: Optional[str] = None
    request_path: Optional[str] = None
    query_params: Optional[str] = None
    
    # Geolocation fields
    geo_country: Optional[str] = "Unknown"
    geo_city: Optional[str] = "Unknown"
    geo_region: Optional[str] = "Unknown"
    geo_isp: Optional[str] = "Unknown"
    geo_asn: Optional[str] = "Unknown"
    geo_lat: Optional[float] = None
    geo_lon: Optional[float] = None
    
    # Raw forensics
    raw_headers: Optional[Dict[str, str]] = None
    mitre_technique: str = "T1552: Unsecured Credentials"
