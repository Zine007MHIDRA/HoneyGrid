import os
import base64
import json
from pathlib import Path
from typing import Optional, Dict, Any
from fastapi import FastAPI, Request, Response, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from honeygrid.config import settings
from honeygrid.database import (
    init_db, get_token, record_incident, list_tokens, list_incidents,
    get_dashboard_stats, update_incident_telemetry,
    create_user, get_user_by_email, get_user_auth_record_by_email, get_user_by_id,
    create_session, get_user_by_session, delete_session
)
from honeygrid.models import IncidentEvent, Token, BrowserTelemetry, User, UserRegister, UserLogin
from honeygrid.core.auth import hash_password, verify_password, generate_captcha, verify_captcha
from honeygrid.core.fingerprint import extract_client_ip, identify_client_tool
from honeygrid.core.geo import lookup_ip_geolocation
from honeygrid.core.threat_intel import analyze_ip_threat
from honeygrid.alerts.discord import send_discord_alert
from honeygrid.core.containment import block_ip
from honeygrid.core.generator import (
    create_web_canary_token, create_aws_honeytoken, create_env_honeytoken,
    create_git_honeytoken, create_keepass_honeytoken, generate_token_download_payload
)
from honeygrid.core.pdf_canary import create_canary_pdf

# Ensure DB initialized on startup
init_db()

app = FastAPI(
    title="HoneyGrid Sentinel",
    description="Deception Sentinel & Multi-Tenant Incident Response SOC Service",
    version="2.0.0"
)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

TRANSPARENT_GIF_BYTES = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")

@app.get("/api/logo")
async def get_brand_logo():
    logo_file = STATIC_DIR / "logo.jpg"
    if logo_file.exists():
        return FileResponse(str(logo_file), media_type="image/jpeg")
    return Response(status_code=404)

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

def get_current_user(request: Request) -> Optional[User]:
    """Resolves authenticated user from HttpOnly session cookie or Authorization header."""
    session_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not session_token:
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            session_token = auth_header[7:].strip()
    if not session_token:
        return None
    return get_user_by_session(session_token)

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

# -------------------------------------------------------------
# Web Navigation Routes (Portal & Dashboard)
# -------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index_root(request: Request):
    """Directs web users to the dashboard if authenticated, otherwise to the login portal."""
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        user = get_current_user(request)
        if user:
            return RedirectResponse(url="/dashboard", status_code=302)
        return RedirectResponse(url="/login", status_code=302)
    return JSONResponse({"service": "HoneyGrid Sentinel SOC", "status": "active", "version": "2.0.0"})

@app.get("/login", response_class=HTMLResponse)
async def login_portal(request: Request):
    """Serves the separate, dedicated HoneyGrid Sentinel Login Portal."""
    user = get_current_user(request)
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)
    html = get_template("login.html")
    if not html:
        return HTMLResponse("<h1>HoneyGrid Login Portal template not found</h1>", status_code=500)
    return HTMLResponse(html)

@app.get("/dashboard", response_class=HTMLResponse)
async def soc_dashboard(request: Request):
    """Serves the Dark-Mode Incident Response Dashboard, guarded by authentication."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    html = get_template("dashboard.html")
    if not html:
        return HTMLResponse("<h1>HoneyGrid Dashboard template not found</h1>", status_code=500)
    return HTMLResponse(html)

@app.get("/health")
async def health_check():
    return {"status": "active", "service": "HoneyGrid Sentinel SOC"}

# -------------------------------------------------------------
# Authentication & Identity Endpoints
# -------------------------------------------------------------

@app.get("/api/auth/captcha")
async def api_captcha():
    """Generates a dynamic visual verification challenge with a signed HMAC token."""
    code, svg, token = generate_captcha(settings.HONEYGRID_SECRET_KEY)
    return {
        "status": "success",
        "captcha_token": token,
        "captcha_svg": svg,
        "expires_in": 300
    }

@app.post("/api/auth/register")
async def api_register(data: UserRegister):
    # 1. Anti-bot honeypot check
    if data.hp_decoy_field:
        return JSONResponse({"status": "error", "message": "Automated bot activity detected and blocked."}, status_code=403)

    # 2. CAPTCHA verification
    if not data.captcha_answer or not data.captcha_token or not verify_captcha(data.captcha_answer, data.captcha_token, settings.HONEYGRID_SECRET_KEY):
        return JSONResponse({"status": "error", "message": "Security verification code is incorrect or expired. Please reload challenge."}, status_code=400)

    email = data.email.strip().lower()
    password = data.password
    if not email or "@" not in email:
        return JSONResponse({"status": "error", "message": "Valid corporate or personal email required"}, status_code=400)
    if len(password) < 6:
        return JSONResponse({"status": "error", "message": "Password must be at least 6 characters"}, status_code=400)
    
    existing = get_user_by_email(email)
    if existing:
        return JSONResponse({"status": "error", "message": "An operator account with this email already exists. Please sign in."}, status_code=400)
    
    # Auto-grant admin role if email matches settings.ADMIN_EMAIL
    role = "admin" if email == settings.ADMIN_EMAIL.lower() else "user"
    pw_hash, salt = hash_password(password)
    user = create_user(email=email, password_hash=pw_hash, salt=salt, role=role)
    
    # Create persistent session
    session_token = create_session(user.id, expire_hours=settings.SESSION_EXPIRE_HOURS)
    
    resp = JSONResponse({
        "status": "success",
        "message": "Operator account provisioned successfully",
        "user": user.model_dump(),
        "redirect": "/dashboard"
    })
    resp.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session_token,
        max_age=settings.SESSION_EXPIRE_HOURS * 3600,
        httponly=True,
        samesite="lax",
        secure=False
    )
    return resp

@app.post("/api/auth/login")
async def api_login(data: UserLogin):
    # 1. Anti-bot honeypot check
    if data.hp_decoy_field:
        return JSONResponse({"status": "error", "message": "Automated bot activity detected and blocked."}, status_code=403)

    # 2. CAPTCHA verification
    if not data.captcha_answer or not data.captcha_token or not verify_captcha(data.captcha_answer, data.captcha_token, settings.HONEYGRID_SECRET_KEY):
        return JSONResponse({"status": "error", "message": "Security verification code is incorrect or expired. Please reload challenge."}, status_code=400)

    email = data.email.strip().lower()
    password = data.password
    if not email or not password:
        return JSONResponse({"status": "error", "message": "Email and password required"}, status_code=400)
    
    record = get_user_auth_record_by_email(email)
    if not record or not verify_password(password, record["password_hash"], record["salt"]):
        return JSONResponse({"status": "error", "message": "Invalid email or access passphrase."}, status_code=401)
    
    user_role = record["role"]
    if email == settings.ADMIN_EMAIL.lower():
        user_role = "admin"
        
    user = User(
        id=record["id"],
        email=record["email"],
        role=user_role,
        created_at=record["created_at"]
    )
    
    expire_hours = settings.SESSION_EXPIRE_HOURS if data.remember_me else 24
    session_token = create_session(user.id, expire_hours=expire_hours)
    resp = JSONResponse({
        "status": "success",
        "message": "Identity authenticated",
        "user": user.model_dump(),
        "redirect": "/dashboard"
    })
    resp.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session_token,
        max_age=expire_hours * 3600,
        httponly=True,
        samesite="lax",
        secure=False
    )
    return resp

@app.post("/api/auth/logout")
async def api_logout(request: Request):
    session_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if session_token:
        delete_session(session_token)
    resp = JSONResponse({"status": "success", "message": "Session terminated", "redirect": "/login"})
    resp.delete_cookie(key=settings.SESSION_COOKIE_NAME)
    return resp

@app.get("/api/auth/me")
async def api_me(request: Request):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"authenticated": False, "user": None}, status_code=401)
    return {"authenticated": True, "user": user.model_dump(), "is_admin": user.is_admin}

# -------------------------------------------------------------
# REST API Endpoints for SOC Dashboard (Multi-Tenant Scoped)
# -------------------------------------------------------------

@app.get("/api/stats")
async def api_stats(request: Request):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return get_dashboard_stats(user_id=user.id, is_admin=user.is_admin)

@app.get("/api/incidents")
async def api_incidents(request: Request, limit: int = 50):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    incidents = list_incidents(user_id=user.id, is_admin=user.is_admin, limit=limit)
    return [i.model_dump() for i in incidents]

@app.get("/api/tokens")
async def api_tokens(request: Request):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    tokens = list_tokens(user_id=user.id, is_admin=user.is_admin)
    return [t.model_dump() for t in tokens]

@app.post("/api/tokens/create")
async def api_create_token(request: Request, data: Dict[str, Any]):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    token_type = data.get("token_type", "web")
    label = data.get("label", f"Decoy-{token_type.upper()}")
    desc = data.get("description", "Generated from Sentinel SOC Dashboard")

    if token_type == "web":
        token, _ = create_web_canary_token(label, desc, owner_id=user.id, owner_email=user.email)
    elif token_type == "aws":
        token, _ = create_aws_honeytoken(label, desc, owner_id=user.id, owner_email=user.email)
    elif token_type == "env":
        token, _ = create_env_honeytoken(label, desc, owner_id=user.id, owner_email=user.email)
    elif token_type == "git":
        token, _ = create_git_honeytoken(f"traps/git_decoy_{label}", label, owner_id=user.id, owner_email=user.email)
    elif token_type == "pdf":
        token, _ = create_canary_pdf(f"traps/{label}.pdf", label, owner_id=user.id, owner_email=user.email)
    elif token_type == "keepass":
        token, _ = create_keepass_honeytoken(f"traps/{label}.kdbx", label, owner_id=user.id, owner_email=user.email)
    else:
        token, _ = create_web_canary_token(label, desc, owner_id=user.id, owner_email=user.email)
        
    return {
        "status": "success",
        "token": token.model_dump(),
        "download_url": f"/api/tokens/{token.id}/download",
        "canary_url": token.metadata.get("canary_url", f"{settings.HONEYGRID_BASE_URL}/t/{token.id}")
    }

@app.get("/api/tokens/{token_id}/download")
async def api_download_token(token_id: str, request: Request):
    """Dynamically generates and downloads the file trap for deployment to disk/storage."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    token = get_token(token_id)
    if not token:
        return JSONResponse({"status": "error", "message": "Honeytoken not found"}, status_code=404)
    
    # Non-admin users cannot download assets owned by someone else
    if not user.is_admin and token.owner_id and token.owner_id != user.id:
        return JSONResponse({"status": "error", "message": "Access denied to this deception asset"}, status_code=403)

    try:
        content_bytes, filename, media_type = generate_token_download_payload(token)
        return Response(
            content=content_bytes,
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0"
            }
        )
    except Exception as e:
        return JSONResponse({"status": "error", "message": f"Failed to generate download: {str(e)}"}, status_code=500)

@app.post("/api/contain/isolate")
async def api_isolate_ip(request: Request, data: Dict[str, Any]):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    ip = data.get("ip")
    if not ip:
        return JSONResponse({"status": "error", "message": "IP required"}, status_code=400)
    result = block_ip(ip)
    return result

# -------------------------------------------------------------
# Deception & Honeytoken Listener Endpoints (PUBLIC CALLBACKS)
# -------------------------------------------------------------

@app.api_route("/t/{token_id}", methods=["GET", "POST", "HEAD"])
async def trigger_canary(
    token_id: str,
    request: Request,
    background_tasks: BackgroundTasks
):
    """
    Primary canary webhook endpoint.
    PUBLIC ACCESS: Intruder callbacks MUST trip freely without authentication!
    """
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
