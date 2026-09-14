from datetime import datetime, timezone
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

class User(BaseModel):
    id: str
    email: str
    role: str = "user"  # "admin" or "user"
    created_at: str

    @property
    def is_admin(self) -> bool:
        return self.role == "admin" or self.email.lower() == "zine.mhidra@gmail.com"

class UserRegister(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

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
    owner_id: Optional[str] = None
    owner_email: Optional[str] = None
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
    
    # Threat Intelligence
    threat_score: int = 15
    connection_type: str = "Unknown"
    is_vpn_proxy: bool = False
    is_tor: bool = False
    
    # Client Hardware & Environment Fingerprint (WebGL, WebRTC, Screen)
    gpu_renderer: Optional[str] = None
    screen_res: Optional[str] = None
    cpu_cores: Optional[int] = None
    device_memory: Optional[int] = None
    local_lan_ip: Optional[str] = None
    client_timezone: Optional[str] = None

    # Raw forensics
    raw_headers: Optional[Dict[str, str]] = None
    mitre_technique: str = "T1552: Unsecured Credentials"

class BrowserTelemetry(BaseModel):
    gpu_renderer: Optional[str] = None
    screen_res: Optional[str] = None
    cpu_cores: Optional[int] = None
    device_memory: Optional[int] = None
    local_lan_ip: Optional[str] = None
    client_timezone: Optional[str] = None
    platform: Optional[str] = None

