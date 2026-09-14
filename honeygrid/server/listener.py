import os
import base64
import json
from pathlib import Path
from typing import Optional, Dict, Any
from fastapi import FastAPI, Request, Response, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from honeygrid.config import settings
from honeygrid.database import (
    init_db, get_token, record_incident, list_tokens, list_incidents,
    get_dashboard_stats, update_incident_telemetry
)
from honeygrid.models import IncidentEvent, Token, BrowserTelemetry
from honeygrid.core.fingerprint import extract_client_ip, identify_client_tool
from honeygrid.core.geo import lookup_ip_geolocation
from honeygrid.core.threat_intel import analyze_ip_threat
from honeygrid.alerts.discord import send_discord_alert
from honeygrid.core.containment import block_ip
from honeygrid.core.generator import (
    create_web_canary_token, create_aws_honeytoken, create_env_honeytoken,
    create_git_honeytoken, create_keepass_honeytoken
)
from honeygrid.core.pdf_canary import create_canary_pdf

# Ensure DB initialized on startup
init_db()

app = FastAPI(
    title="HoneyGrid Sentinel",
    description="Deception Sentinel & Incident Response SOC Service",
    version="2.0.0"
)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
TRANSPARENT_GIF_BYTES = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")

def get_template(name: str) -> str:
    candidate_paths = [
        TEMPLATES_DIR / name,
        Path(os.getcwd()) / "honeygrid" / "server" / "templates" / name,
        Path(__file__).resolve().parent.parent / "templates" / name,
    ]
    for path in candidate_paths:
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception:
                pass
    return ""


def process_incident_async(
    token_id: str,
    raw_ip: str,
    is_local: bool,
    client_tool: str,
    user_agent: str,
    http_method: str,
    request_path: str,
    query_params: str,
    headers_dict: dict
):
    """Background task to resolve GeoIP, threat intel, record incident and dispatch Discord alert."""
    try:
        geo = lookup_ip_geolocation(raw_ip)
        reported_ip = geo.get("query_ip") if is_local and geo.get("query_ip") else raw_ip
        threat_profile = analyze_ip_threat(reported_ip, geo)

        event = IncidentEvent(
            token_id=token_id,
            attacker_ip=reported_ip,
            is_local_ip=is_local,
            client_tool=client_tool,
            user_agent=user_agent,
            http_method=http_method,
            request_path=request_path,
            query_params=query_params,
            geo_country=geo.get("country", "Unknown"),
            geo_city=geo.get("city", "Unknown"),
            geo_region=geo.get("region", "Unknown"),
            geo_isp=geo.get("isp", "Unknown"),
            geo_asn=geo.get("asn", "Unknown"),
            geo_lat=geo.get("lat"),
            geo_lon=geo.get("lon"),
            threat_score=threat_profile.get("threat_score", 15),
            connection_type=threat_profile.get("connection_type", "Unknown"),
            is_vpn_proxy=threat_profile.get("is_vpn_proxy", False),
            is_tor=threat_profile.get("is_tor", False),
            raw_headers=headers_dict,
            mitre_technique="T1552: Unsecured Credentials"
        )
        
        token = get_token(token_id)
        record_incident(event)
        send_discord_alert(event, token)
        print(f"[!] TRIPPED: Token '{token_id}' by IP {reported_ip} [{threat_profile.get('connection_type')} - Threat: {threat_profile.get('threat_score')}%]")
    except Exception as e:
        print(f"[!] Error in background incident processing: {e}")


@app.get("/", response_class=HTMLResponse)
async def index_root(request: Request):
    """Redirects web visitors to the interactive SOC dashboard."""
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return RedirectResponse(url="/dashboard")
    return JSONResponse({"service": "HoneyGrid Sentinel SOC", "status": "active", "version": "2.0.0"})

@app.get("/dashboard", response_class=HTMLResponse)
async def soc_dashboard():
    """Serves the Dark-Mode Incident Response Dashboard."""
    html = get_template("dashboard.html")
    if not html:
        return HTMLResponse("<h1>HoneyGrid Dashboard template not found</h1>", status_code=500)
    return HTMLResponse(html)

@app.get("/health")
async def health_check():
    return {"status": "active", "service": "HoneyGrid Sentinel SOC"}

# -------------------------------------------------------------
# REST API Endpoints for SOC Dashboard & External Integrations
# -------------------------------------------------------------

@app.get("/api/stats")
async def api_stats():
    return get_dashboard_stats()

@app.get("/api/incidents")
async def api_incidents(limit: int = 50):
    incidents = list_incidents(limit=limit)
    return [i.model_dump() for i in incidents]

@app.get("/api/tokens")
async def api_tokens():
    tokens = list_tokens()
    return [t.model_dump() for t in tokens]

@app.post("/api/tokens/create")
async def api_create_token(data: Dict[str, Any]):
    token_type = data.get("token_type", "web")
    label = data.get("label", f"Decoy-{token_type.upper()}")
    desc = data.get("description", "Generated from Sentinel SOC Dashboard")

    if token_type == "web":
        token, _ = create_web_canary_token(label, desc)
    elif token_type == "aws":
        token, _ = create_aws_honeytoken(label, desc)
    elif token_type == "env":
        token, _ = create_env_honeytoken(label, desc)
    elif token_type == "git":
        token, _ = create_git_honeytoken(f"traps/git_decoy_{label}", label)
    elif token_type == "pdf":
        token, _ = create_canary_pdf(f"traps/{label}.pdf", label)
    else:
        token, _ = create_web_canary_token(label, desc)
        
    return {"status": "success", "token": token.model_dump()}

@app.post("/api/contain/isolate")
async def api_isolate_ip(data: Dict[str, Any]):
    ip = data.get("ip")
    if not ip:
        return JSONResponse({"status": "error", "message": "IP required"}, status_code=400)
    result = block_ip(ip)
    return result

# -------------------------------------------------------------
# Deception & Honeytoken Listener Endpoints
# -------------------------------------------------------------

@app.api_route("/t/{token_id}", methods=["GET", "POST", "HEAD"])
async def trigger_canary(
    token_id: str,
    request: Request,
    background_tasks: BackgroundTasks
):
    """Primary canary webhook endpoint."""
    raw_ip, is_local = extract_client_ip(request)
    headers_dict = dict(request.headers)
    user_agent = headers_dict.get("user-agent", "")
    client_tool = identify_client_tool(user_agent)
    
    # Enqueue heavy telemetry resolution, GeoIP, threat intel, and Discord alerting to background
    background_tasks.add_task(
        process_incident_async,
        token_id=token_id,
        raw_ip=raw_ip,
        is_local=is_local,
        client_tool=client_tool,
        user_agent=user_agent,
        http_method=request.method,
        request_path=str(request.url.path),
        query_params=str(request.url.query),
        headers_dict=headers_dict
    )

    accept = headers_dict.get("accept", "")
    
    # 1. If requested by image / document or explicitly labeled as pdf/pixel
    if "image" in accept or request.query_params.get("source") == "pdf":
        return Response(content=TRANSPARENT_GIF_BYTES, media_type="image/gif")

    # 2. If requested by a human browser, serve deceptive corporate 401 page with silent hardware beacon
    if "text/html" in accept:
        template = get_template("decoy.html")
        if template:
            html = template.replace("{{ token_id }}", token_id)
            return HTMLResponse(content=html, status_code=401)

    # 3. For API or CLI tools (curl, python), return deceptive JSON error
    return JSONResponse(
        status_code=401,
        content={"error": "Unauthorized", "message": "Invalid token or expired session credential."}
    )

@app.post("/t/{token_id}/telemetry")
async def receive_browser_telemetry(
    token_id: str,
    telemetry: BrowserTelemetry
):
    """Silent collector endpoint for client-side GPU, screen, and WebRTC LAN leaks."""
    update_incident_telemetry(token_id, telemetry)
    return {"status": "received"}

@app.api_route("/api/v1/auth/{path:path}", methods=["GET", "POST"])
async def decoy_auth_endpoint(path: str, request: Request, background_tasks: BackgroundTasks):
    return await trigger_canary("canary_api_auth_trap", request, background_tasks)

@app.api_route("/.env", methods=["GET"])
async def decoy_env_endpoint(request: Request, background_tasks: BackgroundTasks):
    return await trigger_canary("scanner_env_probe", request, background_tasks)
