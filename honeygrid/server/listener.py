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
    create_session, get_user_by_session, delete_session,
    add_safe_ip, remove_safe_ip, list_safe_ips, is_safe_ip,
    list_audit_logs
)
from honeygrid.models import IncidentEvent, Token, BrowserTelemetry, User, UserRegister, UserLogin
from honeygrid.core.auth import hash_password, verify_password, generate_captcha, verify_captcha
from honeygrid.core.rate_limit import login_limiter
from honeygrid.core.fingerprint import extract_client_ip, identify_client_tool
from honeygrid.core.audit import log_audit_event
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

def is_https_request(request: Request) -> bool:
    """Detects whether request reached service over HTTPS (direct or through cloud reverse proxy)."""
    proto = request.headers.get("x-forwarded-proto", "").lower()
    ssl = request.headers.get("x-forwarded-ssl", "").lower()
    return request.url.scheme == "https" or proto == "https" or ssl == "on"

@app.middleware("http")
async def enterprise_security_headers_middleware(request: Request, call_next):
    """
    Applies defense-in-depth HTTP security headers for operator sessions,
    and deceptive stealth cloaking on public canary tripwire endpoints.
    """
    response = await call_next(request)
    
    path = request.url.path
    is_canary = path.startswith("/t/") or path == "/.env" or path.startswith("/api/v1/auth")
    
    if is_canary:
        # DECEPTION STEALTH MODE: Cloak framework and disguise as production web server
        response.headers["Server"] = "nginx/1.24.0 (Ubuntu)"
        if "x-powered-by" in response.headers:
            del response.headers["x-powered-by"]
    else:
        # OPERATOR DEFENSE HEADERS: Block clickjacking, MIME sniffing, and unauthorized framing
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https://*.cartocdn.com https://*.openstreetmap.org; "
            "connect-src 'self' https://*.cartocdn.com; "
            "frame-ancestors 'none'; "
            "base-uri 'self';"
        )
        if is_https_request(request):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

    return response

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"
try:
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    pass
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
    """
    Background task to resolve GeoIP, threat intel, record incident and dispatch Discord alert.
    Hardened with isolated try/except blocks so failure in network lookups or Discord never
    prevents database incident recording.
    """
    try:
        try:
            geo = lookup_ip_geolocation(raw_ip)
        except Exception as ge:
            print(f"[!] GeoIP lookup failed: {ge}")
            geo = {"ip": raw_ip, "country": "Unknown", "city": "Unknown", "region": "Unknown", "isp": "Unknown", "asn": "Unknown"}

        reported_ip = geo.get("query_ip") if is_local and geo.get("query_ip") else raw_ip
        try:
            threat_profile = analyze_ip_threat(reported_ip, geo)
        except Exception as te:
            print(f"[!] Threat analysis failed: {te}")
            threat_profile = {"threat_score": 15, "connection_type": "Direct Unknown", "is_vpn_proxy": False, "is_tor": False}

        # Check if caller IP is on Operator Safe List
        is_safe = is_safe_ip(reported_ip)
        threat_score = 0 if is_safe else threat_profile.get("threat_score", 15)
        connection_type = "Authorized Operator Test" if is_safe else threat_profile.get("connection_type", "Unknown")
        mitre = "Audit / Authorized Operator Validation" if is_safe else "T1552: Unsecured Credentials"

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
            threat_score=threat_score,
            connection_type=connection_type,
            is_vpn_proxy=False if is_safe else threat_profile.get("is_vpn_proxy", False),
            is_tor=False if is_safe else threat_profile.get("is_tor", False),
            raw_headers=headers_dict,
            mitre_technique=mitre
        )
        
        token = get_token(token_id)
        record_incident(event)
        
        try:
            send_discord_alert(event, token)
        except Exception as de:
            print(f"[!] Discord alerting failed: {de}")
            
        print(f"[!] TRIPPED: Token '{token_id}' by IP {reported_ip} [{threat_profile.get('connection_type')} - Threat: {threat_profile.get('threat_score')}%]")
    except Exception as e:
        print(f"[!] Critical error in background incident processing: {e}")
        log_audit_event(
            action="CANARY_PROCESSING_FAILURE",
            outcome="FAILURE",
            actor="system",
            client_ip=raw_ip,
            target=token_id,
            metadata={"error": str(e), "path": request_path}
        )

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
async def api_register(data: UserRegister, request: Request):
    client_ip, _ = extract_client_ip(request)
    email = data.email.strip().lower() if data.email else ""

    # 1. Anti-bot honeypot check
    if data.hp_decoy_field:
        log_audit_event("AUTH_REGISTER_BOT_BLOCKED", "BLOCKED", actor=email or "unknown", client_ip=client_ip)
        return JSONResponse({"status": "error", "message": "Automated bot activity detected and blocked."}, status_code=403)

    # 2. CAPTCHA verification
    if not data.captcha_answer or not data.captcha_token or not verify_captcha(data.captcha_answer, data.captcha_token, settings.HONEYGRID_SECRET_KEY):
        log_audit_event("AUTH_REGISTER_FAILURE", "FAILURE", actor=email or "unknown", client_ip=client_ip, metadata={"reason": "captcha_invalid"})
        return JSONResponse({"status": "error", "message": "Security verification code is incorrect or expired. Please reload challenge."}, status_code=400)

    password = data.password
    if not email or "@" not in email:
        log_audit_event("AUTH_REGISTER_FAILURE", "FAILURE", actor=email or "unknown", client_ip=client_ip, metadata={"reason": "invalid_email"})
        return JSONResponse({"status": "error", "message": "Valid corporate or personal email required"}, status_code=400)
    if len(password) < 6:
        log_audit_event("AUTH_REGISTER_FAILURE", "FAILURE", actor=email, client_ip=client_ip, metadata={"reason": "password_too_short"})
        return JSONResponse({"status": "error", "message": "Password must be at least 6 characters"}, status_code=400)
    
    existing = get_user_by_email(email)
    if existing:
        log_audit_event("AUTH_REGISTER_FAILURE", "FAILURE", actor=email, client_ip=client_ip, metadata={"reason": "user_already_exists"})
        return JSONResponse({"status": "error", "message": "An operator account with this email already exists. Please sign in."}, status_code=400)
    
    # Auto-grant admin role if email matches settings.ADMIN_EMAIL
    role = "admin" if email == settings.ADMIN_EMAIL.lower() else "user"
    pw_hash, salt = hash_password(password)
    user = create_user(email=email, password_hash=pw_hash, salt=salt, role=role)
    
    # Create persistent session
    session_token = create_session(user.id, expire_hours=settings.SESSION_EXPIRE_HOURS)
    log_audit_event("AUTH_REGISTER_SUCCESS", "SUCCESS", actor=user.email, client_ip=client_ip, target=str(user.id), metadata={"role": user.role})
    
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
        secure=is_https_request(request)
    )
    return resp

@app.post("/api/auth/login")
async def api_login(data: UserLogin, request: Request):
    client_ip, _ = extract_client_ip(request)
    email = data.email.strip().lower() if data.email else ""

    # 0. Brute-Force Rate Limiting & Lockout Check
    is_locked, remaining = login_limiter.is_locked(client_ip)
    if is_locked:
        log_audit_event("RATE_LIMIT_LOCKOUT", "BLOCKED", actor=email or "unknown", client_ip=client_ip, metadata={"remaining_seconds": remaining})
        return JSONResponse(
            {
                "status": "error",
                "message": f"Too many failed login attempts. Temporarily locked for {remaining} seconds to safeguard your account."
            },
            status_code=429,
            headers={"Retry-After": str(remaining)}
        )

    # 1. Anti-bot honeypot check
    if data.hp_decoy_field:
        login_limiter.record_failure(client_ip)
        log_audit_event("AUTH_LOGIN_BOT_BLOCKED", "BLOCKED", actor=email or "unknown", client_ip=client_ip)
        return JSONResponse({"status": "error", "message": "Automated bot activity detected and blocked."}, status_code=403)

    # 2. CAPTCHA verification
    if not data.captcha_answer or not data.captcha_token or not verify_captcha(data.captcha_answer, data.captcha_token, settings.HONEYGRID_SECRET_KEY):
        log_audit_event("AUTH_LOGIN_CAPTCHA_FAIL", "FAILURE", actor=email or "unknown", client_ip=client_ip)
        return JSONResponse({"status": "error", "message": "Security verification code is incorrect or expired. Please reload challenge."}, status_code=400)

    password = data.password
    if not email or not password:
        log_audit_event("AUTH_LOGIN_FAILURE", "FAILURE", actor=email or "unknown", client_ip=client_ip, metadata={"reason": "missing_credentials"})
        return JSONResponse({"status": "error", "message": "Email and password required"}, status_code=400)
    
    record = get_user_auth_record_by_email(email)
    if not record or not verify_password(password, record["password_hash"], record["salt"]):
        failures = login_limiter.record_failure(client_ip)
        log_audit_event("AUTH_LOGIN_FAILURE", "FAILURE", actor=email, client_ip=client_ip, metadata={"failures": failures})
        remaining_attempts = max(0, 5 - failures)
        msg = "Invalid email or access passphrase."
        if 0 < remaining_attempts < 4:
            msg += f" {remaining_attempts} attempt(s) remaining before temporary lockout."
        return JSONResponse({"status": "error", "message": msg}, status_code=401)

    # Successful login: reset rate limit strikes
    login_limiter.record_success(client_ip)
    
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
    log_audit_event("AUTH_LOGIN_SUCCESS", "SUCCESS", actor=user.email, client_ip=client_ip, target=str(user.id), metadata={"role": user.role})
    
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
        secure=is_https_request(request)
    )
    return resp

@app.post("/api/auth/logout")
async def api_logout(request: Request):
    client_ip, _ = extract_client_ip(request)
    user = get_current_user(request)
    session_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if session_token:
        delete_session(session_token)
    log_audit_event("AUTH_LOGOUT", "SUCCESS", actor=user.email if user else "session", client_ip=client_ip)
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


# -------------------------------------------------------------
# Operator Safe List Endpoints (Allowlist Management)
# -------------------------------------------------------------

@app.get("/api/safelist")
async def api_get_safelist(request: Request):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    client_ip, _ = extract_client_ip(request)
    return {
        "status": "success",
        "safe_ips": list_safe_ips(),
        "client_ip": client_ip,
        "is_client_safe": is_safe_ip(client_ip)
    }

@app.post("/api/safelist/add")
async def api_add_safelist(request: Request, data: Dict[str, Any]):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    
    client_ip, _ = extract_client_ip(request)
    ip = data.get("ip") or client_ip
    label = data.get("label", f"Operator Workstation ({user.email})")
    
    success = add_safe_ip(ip, label=label, added_by=user.email)
    log_audit_event("SAFELIST_ADD", "SUCCESS" if success else "FAILURE", actor=user.email, client_ip=client_ip, target=ip, metadata={"label": label})
    if success:
        return {"status": "success", "message": f"IP {ip} added to Operator Safe List."}
    return JSONResponse({"status": "error", "message": "Invalid IP address"}, status_code=400)

@app.post("/api/safelist/remove")
async def api_remove_safelist(request: Request, data: Dict[str, Any]):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    
    client_ip, _ = extract_client_ip(request)
    ip = data.get("ip")
    if not ip:
        return JSONResponse({"status": "error", "message": "IP required"}, status_code=400)
        
    removed = remove_safe_ip(ip)
    log_audit_event("SAFELIST_REMOVE", "SUCCESS" if removed else "NOT_FOUND", actor=user.email, client_ip=client_ip, target=ip)
    return {"status": "success", "removed": removed, "message": f"IP {ip} removed from Operator Safe List."}

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

@app.get("/api/audit-logs")
async def api_get_audit_logs(request: Request, limit: int = 50, action: Optional[str] = None):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    logs = list_audit_logs(limit=limit, action=action)
    return {"status": "success", "audit_logs": logs}

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

    client_ip, _ = extract_client_ip(request)
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
        
    log_audit_event("TOKEN_CREATE", "SUCCESS", actor=user.email, client_ip=client_ip, target=token.id, metadata={"type": token_type, "label": label})

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

    client_ip, _ = extract_client_ip(request)
    ip = data.get("ip")
    if not ip:
        return JSONResponse({"status": "error", "message": "IP required"}, status_code=400)
        
    log_audit_event("CONTAINMENT_ATTEMPT", "ATTEMPT", actor=user.email, client_ip=client_ip, target=ip)

    # Operator Safety: Block isolation if IP is on Safe List
    if is_safe_ip(ip):
        log_audit_event("CONTAINMENT_BLOCKED", "BLOCKED_SAFELIST", actor=user.email, client_ip=client_ip, target=ip, metadata={"reason": "safelist"})
        return JSONResponse({
            "status": "error",
            "applied": False,
            "message": f"IP {ip} is on the Operator Safe List. Auto-containment blocked to safeguard operator connectivity."
        }, status_code=400)

    result = block_ip(ip)
    log_audit_event("CONTAINMENT_RESULT", "SUCCESS" if result.get("applied") else "NO_OP", actor=user.email, client_ip=client_ip, target=ip, metadata=result)
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
