import base64
from typing import Optional
from fastapi import FastAPI, Request, Response, BackgroundTasks
from fastapi.responses import JSONResponse, Response
from honeygrid.config import settings
from honeygrid.database import get_token, record_incident
from honeygrid.models import IncidentEvent
from honeygrid.core.fingerprint import extract_client_ip, identify_client_tool
from honeygrid.core.geo import lookup_ip_geolocation
from honeygrid.alerts.discord import send_discord_alert

app = FastAPI(
    title="HoneyGrid Canary Sentinel",
    description="High-fidelity Canary & Honeytoken Listener Service",
    version="1.0.0"
)

# 1x1 Transparent GIF for pixel tracking (in documents or emails)
TRANSPARENT_GIF_BYTES = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")

def process_incident_telemetry(event: IncidentEvent):
    """Background task to record incident and dispatch Discord alert."""
    token = get_token(event.token_id)
    # Save to database
    record_incident(event)
    # Dispatch Discord alert
    send_discord_alert(event, token)
    print(f"[!] TRIPPED: Token '{event.token_id}' by IP {event.attacker_ip} ({event.client_tool})")

@app.get("/health")
async def health_check():
    return {"status": "active", "service": "HoneyGrid Canary Sentinel"}

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
    
    # Geolocation lookup
    geo = lookup_ip_geolocation(raw_ip)
    
    # If the request was local, geo might resolve our public test IP for realism
    reported_ip = geo.get("query_ip") if is_local and geo.get("query_ip") else raw_ip

    event = IncidentEvent(
        token_id=token_id,
        attacker_ip=reported_ip,
        is_local_ip=is_local,
        client_tool=client_tool,
        user_agent=user_agent,
        http_method=request.method,
        request_path=str(request.url.path),
        query_params=str(request.url.query),
        geo_country=geo.get("country", "Unknown"),
        geo_city=geo.get("city", "Unknown"),
        geo_region=geo.get("region", "Unknown"),
        geo_isp=geo.get("isp", "Unknown"),
        geo_asn=geo.get("asn", "Unknown"),
        geo_lat=geo.get("lat"),
        geo_lon=geo.get("lon"),
        raw_headers=headers_dict,
        mitre_technique="T1552: Unsecured Credentials"
    )
    
    background_tasks.add_task(process_incident_telemetry, event)

    # If requested by image/document or asking for image, return 1x1 GIF
    accept = headers_dict.get("accept", "")
    if "image" in accept or request.query_params.get("source") == "pdf":
        return Response(content=TRANSPARENT_GIF_BYTES, media_type="image/gif")

    # Otherwise return a realistic, deceptive 401 Unauthorized or 404
    return JSONResponse(
        status_code=401,
        content={"error": "Unauthorized", "message": "Invalid token or expired session credential."}
    )

@app.api_route("/api/v1/auth/{path:path}", methods=["GET", "POST"])
async def decoy_auth_endpoint(path: str, request: Request, background_tasks: BackgroundTasks):
    """Decoy authentication endpoint for API key / credential traps."""
    return await trigger_canary("canary_api_auth_trap", request, background_tasks)

@app.api_route("/.env", methods=["GET"])
async def decoy_env_endpoint(request: Request, background_tasks: BackgroundTasks):
    """Catches automated scanners probing for exposed environment files."""
    return await trigger_canary("scanner_env_probe", request, background_tasks)
