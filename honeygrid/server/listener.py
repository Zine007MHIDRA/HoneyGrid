import os
import re
import html
import base64
import json
import time
import secrets
from pathlib import Path
from typing import Optional, Dict, Any
from fastapi import FastAPI, Request, Response, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from honeygrid.config import settings
from honeygrid.database import (
    init_db, get_token, record_incident, list_tokens, list_incidents,
    get_incident, list_incidents_by_ip,
    get_dashboard_stats, update_incident_telemetry,
    create_user, get_user_by_email, get_user_auth_record_by_email, get_user_by_id,
    create_session, get_user_by_session, delete_session,
    add_safe_ip, remove_safe_ip, list_safe_ips, is_safe_ip, is_safe_ip_for_owner,
    list_audit_logs, consume_captcha,
    delete_user_sessions, get_user_auth_record_by_id, set_user_password, list_users,
    create_password_reset, consume_password_reset
)
from urllib.parse import urlsplit
from honeygrid.models import IncidentEvent, Token, BrowserTelemetry, User, UserRegister, UserLogin
from honeygrid.core.auth import hash_password, verify_password, generate_captcha, verify_captcha, burn_password_check, captcha_signature, needs_rehash
from honeygrid.core.rate_limit import login_limiter, account_limiter, register_limiter, captcha_limiter, canary_limiter, telemetry_limiter, alert_limiter, reset_ip_limiter, reset_email_limiter
from honeygrid.core.fingerprint import extract_client_ip, identify_client_tool, ip_in_networks
from honeygrid.core.redact import redact_headers
from honeygrid.core.audit import log_audit_event
from honeygrid.core.geo import lookup_ip_geolocation
from honeygrid.core.threat_intel import analyze_ip_threat
from honeygrid.alerts.discord import send_discord_alert, send_discord_signup_alert
from honeygrid.alerts.email import send_password_reset_email
from honeygrid.core.containment import block_ip, validate_containment_ip
from honeygrid.core.generator import (
    create_web_canary_token, create_aws_honeytoken, create_env_honeytoken,
    create_git_honeytoken, create_keepass_honeytoken, generate_token_download_payload
)
from honeygrid.core.pdf_canary import create_canary_pdf

# Ensure DB initialized on startup
init_db()

if not settings.SECRET_KEY_CONFIGURED:
    print("[!] HONEYGRID_SECRET_KEY is not set. "
          + ("Sign-in and registration are disabled until it is configured." if settings.IS_PRODUCTION
             else "Using a random per-process key (fine for local development only)."))

app = FastAPI(
    title="HoneyGrid Sentinel",
    description="Deception Sentinel & Multi-Tenant Incident Response SOC Service",
    version="2.0.0"
)

def is_https_request(request: Request) -> bool:
    """True when the request reached the service over HTTPS. Forwarded-protocol headers are only
    believed from a configured proxy; production (Vercel) is always HTTPS at the edge."""
    if request.url.scheme == "https" or settings.IS_PRODUCTION:
        return True
    peer = request.client.host if request.client else ""
    if peer and ip_in_networks(peer, settings.get_trusted_proxies() + settings.get_cloudflare_proxies()):
        proto = request.headers.get("x-forwarded-proto", "").lower()
        ssl = request.headers.get("x-forwarded-ssl", "").lower()
        return proto == "https" or ssl == "on"
    return False

NO_STORE_PREFIXES = ("/api/auth", "/api/admin", "/api/stats", "/api/incidents", "/api/tokens", "/api/safelist", "/api/audit-logs", "/api/contain")

# While an operator is on a temporary password (after an admin reset), these are the only API calls allowed
PASSWORD_CHANGE_ALLOWED = ("/api/auth/me", "/api/auth/change-password", "/api/auth/logout", "/api/auth/captcha", "/api/auth/login")

def session_token_from(request: Request) -> Optional[str]:
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not token:
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
    return token or None

STATE_CHANGING = ("POST", "PUT", "PATCH", "DELETE")
MAX_BODY_BYTES = 64 * 1024

@app.middleware("http")
async def request_guard_middleware(request: Request, call_next):
    """Two cheap guards before any route runs:
    1. Bodies over 64 KB are refused (nothing legitimate here is larger; canary floods are).
    2. CSRF: a state-changing /api call carrying an Origin or Referer from another site is refused.
       Browsers always attach one of them to cross-site requests; CLI clients send neither."""
    path = request.scope.get("path", "")
    length = request.headers.get("content-length", "")
    if length.isdigit() and int(length) > MAX_BODY_BYTES:
        return JSONResponse({"error": "Request too large"}, status_code=413)

    if request.method in STATE_CHANGING and path.startswith("/api/") and not path.startswith("/api/v1/auth"):
        source = request.headers.get("origin") or request.headers.get("referer") or ""
        if source and source != "null":
            source_host = urlsplit(source).netloc.lower()
            own_hosts = {(request.headers.get("host") or "").lower()}
            if settings.IS_PRODUCTION:
                # Vercel's edge forwards the public hostname here
                own_hosts.add((request.headers.get("x-forwarded-host") or "").lower())
            own_hosts.discard("")
            if source_host not in own_hosts:
                return JSONResponse({"error": "Cross-site request refused"}, status_code=403)
        elif source == "null":
            return JSONResponse({"error": "Cross-site request refused"}, status_code=403)
    return await call_next(request)

@app.middleware("http")
async def require_password_change_middleware(request: Request, call_next):
    path = request.scope.get("path", "")
    if path.startswith("/api/") and not path.startswith("/api/v1/auth") and path not in PASSWORD_CHANGE_ALLOWED:
        token = session_token_from(request)
        if token:
            user = get_user_by_session(token)
            record = get_user_auth_record_by_id(user.id) if user else None
            if record and record.get("must_change_password"):
                return JSONResponse({"error": "password_change_required",
                                     "message": "Choose a new password before continuing."}, status_code=403)
    return await call_next(request)

@app.middleware("http")
async def enterprise_security_headers_middleware(request: Request, call_next):
    """
    Applies defense-in-depth HTTP security headers for operator sessions,
    and deceptive stealth cloaking on public canary tripwire endpoints.
    """
    # Per-request nonce: only <script> tags the server stamped with it may run on operator pages
    request.state.csp_nonce = secrets.token_urlsafe(18)
    response = await call_next(request)

    path = request.url.path
    is_canary = path.startswith("/t/") or path == "/.env" or path.startswith("/api/v1/auth")
    
    if is_canary:
        # DECEPTION STEALTH MODE: Cloak framework and disguise as production web server
        response.headers["Server"] = "nginx/1.24.0 (Ubuntu)"
        if "x-powered-by" in response.headers:
            del response.headers["x-powered-by"]
        # Headers an ordinary nginx site would send; they also contain anything reflected on the decoy page
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        )
    else:
        # OPERATOR DEFENSE HEADERS: Block clickjacking, MIME sniffing, and unauthorized framing
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{request.state.csp_nonce}' https://unpkg.com/leaflet@1.9.4/; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com/leaflet@1.9.4/; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https://*.cartocdn.com https://*.openstreetmap.org; "
            "connect-src 'self' https://*.cartocdn.com; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "object-src 'none';"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if path.startswith(NO_STORE_PREFIXES) or path in ("/login", "/dashboard", "/reset-password"):
            response.headers.setdefault("Cache-Control", "no-store")
        if path in ("/login", "/dashboard", "/reset-password"):
            response.headers["X-Robots-Tag"] = "noindex, nofollow"
        if path == "/reset-password":
            response.headers["Referrer-Policy"] = "no-referrer"
        if is_https_request(request):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

    return response

@app.middleware("http")
async def normalize_serverless_routing_middleware(request: Request, call_next):
    """
    Normalizes request paths if routed through serverless rewrites
    (e.g., /api/index.py, /api/index, /index.py) to prevent 404 Not Found on cloud deployments.
    """
    path = request.scope.get("path", "")
    for prefix in ["/api/index.py", "/api/index", "/index.py"]:
        if path == prefix:
            request.scope["path"] = "/"
            break
        elif path.startswith(prefix + "/"):
            request.scope["path"] = path[len(prefix):]
            break
    return await call_next(request)

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

@app.get("/ui/theme.css")
async def get_theme_stylesheet():
    """Shared design tokens, served through a route (not /static) so it resolves on Vercel."""
    css = get_template("theme.css")
    if not css:
        return Response(status_code=404)
    return Response(content=css, media_type="text/css", headers={"Cache-Control": "public, max-age=300"})

def render_page(name: str, request: Request) -> str:
    """Operator/landing templates with every <script> stamped with this request's CSP nonce."""
    html = get_template(name)
    nonce = getattr(request.state, "csp_nonce", "")
    return html.replace("<script>", f'<script nonce="{nonce}">').replace("<script src=", f'<script nonce="{nonce}" src=')

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
    headers_dict: dict,
    geo_headers: Optional[dict] = None
):
    """
    Background task to resolve GeoIP, threat intel, record incident and dispatch Discord alert.
    Hardened with isolated try/except blocks so failure in network lookups or Discord never
    prevents database incident recording.
    """
    try:
        try:
            # Private callers are never resolved to the server's own public IP (isolating that would
            # block the sensor itself); edge geo headers are only used when the edge is trusted.
            geo = lookup_ip_geolocation(raw_ip, fallback_to_public=False, headers=headers_dict if geo_headers is None else geo_headers)
        except Exception as ge:
            print(f"[!] GeoIP lookup failed: {ge}")
            geo = {"ip": raw_ip, "country": "Unknown", "city": "Unknown", "region": "Unknown", "isp": "Unknown", "asn": "Unknown"}

        reported_ip = raw_ip
        try:
            threat_profile = analyze_ip_threat(reported_ip, geo)
        except Exception as te:
            print(f"[!] Threat analysis failed: {te}")
            threat_profile = {"threat_score": 15, "connection_type": "Direct Unknown", "is_vpn_proxy": False, "is_tor": False}

        # Check if caller IP is on Operator Safe List
        token = get_token(token_id)
        is_safe = is_safe_ip_for_owner(reported_ip, token.owner_id if token else None)
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
        
        record_incident(event)
        
        try:
            # One Discord alert per attacker + decoy per 5 minutes, so floods can't drown the channel
            alert_key = f"{reported_ip}|{token_id}"
            if not alert_limiter.is_locked(alert_key)[0]:
                alert_limiter.record_failure(alert_key)
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
@app.get("/api/index.py", response_class=HTMLResponse)
@app.get("/api/index", response_class=HTMLResponse)
@app.get("/index.py", response_class=HTMLResponse)
async def index_root(request: Request):
    """Sends signed-in operators to the dashboard; everyone else browsing gets the product landing page."""
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        user = get_current_user(request)
        if user:
            return RedirectResponse(url="/dashboard", status_code=302)
        html = render_page("landing.html", request)
        if html:
            return HTMLResponse(html)
        return RedirectResponse(url="/login", status_code=302)
    return JSONResponse({"service": "HoneyGrid Sentinel SOC", "status": "active", "version": "2.0.0"})

@app.get("/login", response_class=HTMLResponse)
async def login_portal(request: Request):
    """Serves the separate, dedicated HoneyGrid Sentinel Login Portal."""
    user = get_current_user(request)
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)
    html = render_page("login.html", request)
    if not html:
        return HTMLResponse("<h1>HoneyGrid Login Portal template not found</h1>", status_code=500)
    return HTMLResponse(html)

@app.get("/dashboard", response_class=HTMLResponse)
async def soc_dashboard(request: Request):
    """Serves the Dark-Mode Incident Response Dashboard, guarded by authentication."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    html = render_page("dashboard.html", request)
    if not html:
        return HTMLResponse("<h1>HoneyGrid Dashboard template not found</h1>", status_code=500)
    return HTMLResponse(html)

@app.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(request: Request):
    """The reset token travels in the URL fragment (#token=...), which browsers never send to servers."""
    html = render_page("reset.html", request)
    if not html:
        return HTMLResponse("<h1>Reset page template not found</h1>", status_code=500)
    return HTMLResponse(html)

@app.get("/health")
async def health_check():
    return {"status": "active", "service": "HoneyGrid Sentinel SOC"}

# -------------------------------------------------------------
# Authentication & Identity Endpoints
# -------------------------------------------------------------

AUTH_UNAVAILABLE = {"status": "error", "message": "Sign-in is temporarily unavailable. The server is missing its secret key configuration."}
TOO_MANY_ATTEMPTS = "Too many attempts. Wait a few minutes and try again."
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")

def auth_configured() -> bool:
    """In production the captcha key must come from the environment, or every instance signs with its own."""
    return settings.SECRET_KEY_CONFIGURED or not settings.IS_PRODUCTION

def check_captcha(answer: Optional[str], token: Optional[str]) -> bool:
    """Valid, unexpired AND never used before. Every presented token is burned, right or wrong."""
    if not answer or not token:
        return False
    sig = captcha_signature(token)
    if not sig or not consume_captcha(sig, time.time() + 330):
        return False
    return verify_captcha(answer, token, settings.HONEYGRID_SECRET_KEY)

def set_session_cookie(resp: Response, request: Request, token: str, hours: int):
    resp.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=token,
        max_age=hours * 3600,
        httponly=True,
        samesite="strict",
        secure=is_https_request(request)
    )

def too_many(remaining: int) -> JSONResponse:
    return JSONResponse({"status": "error", "message": TOO_MANY_ATTEMPTS}, status_code=429, headers={"Retry-After": str(max(1, remaining))})

@app.get("/api/auth/captcha")
async def api_captcha(request: Request):
    """Generates a dynamic visual verification challenge with a signed HMAC token."""
    if not auth_configured():
        return JSONResponse(AUTH_UNAVAILABLE, status_code=503)
    client_ip, _ = extract_client_ip(request)
    locked, remaining = captcha_limiter.is_locked(client_ip)
    if locked:
        return too_many(remaining)
    captcha_limiter.record_failure(client_ip)
    code, svg, token = generate_captcha(settings.HONEYGRID_SECRET_KEY)
    return {
        "status": "success",
        "captcha_token": token,
        "captcha_svg": svg,
        "expires_in": 300
    }

@app.post("/api/auth/register")
async def api_register(data: UserRegister, request: Request, background_tasks: BackgroundTasks):
    if not auth_configured():
        return JSONResponse(AUTH_UNAVAILABLE, status_code=503)
    client_ip, _ = extract_client_ip(request)
    email = data.email.strip().lower() if data.email else ""

    # 0. Registration rate limit: every attempt counts, successful or not
    locked, remaining = register_limiter.is_locked(client_ip)
    if locked:
        log_audit_event("AUTH_REGISTER_RATE_LIMIT", "BLOCKED", actor=email or "unknown", client_ip=client_ip)
        return too_many(remaining)
    register_limiter.record_failure(client_ip)

    # 1. Anti-bot honeypot check
    if data.hp_decoy_field:
        log_audit_event("AUTH_REGISTER_BOT_BLOCKED", "BLOCKED", actor=email or "unknown", client_ip=client_ip)
        return JSONResponse({"status": "error", "message": "Automated bot activity detected and blocked."}, status_code=403)

    # 2. CAPTCHA verification
    if not check_captcha(data.captcha_answer, data.captcha_token):
        log_audit_event("AUTH_REGISTER_FAILURE", "FAILURE", actor=email or "unknown", client_ip=client_ip, metadata={"reason": "captcha_invalid"})
        return JSONResponse({"status": "error", "message": "Security verification code is incorrect or expired. Please reload challenge."}, status_code=400)

    password = data.password or ""
    if not email or len(email) > 254 or not EMAIL_PATTERN.match(email):
        log_audit_event("AUTH_REGISTER_FAILURE", "FAILURE", actor=email or "unknown", client_ip=client_ip, metadata={"reason": "invalid_email"})
        return JSONResponse({"status": "error", "message": "Enter a valid email address."}, status_code=400)
    if len(password) < 12 or len(password) > 256:
        log_audit_event("AUTH_REGISTER_FAILURE", "FAILURE", actor=email, client_ip=client_ip, metadata={"reason": "password_length"})
        return JSONResponse({"status": "error", "message": "Passwords must be 12 to 256 characters long."}, status_code=400)

    # The admin address is reserved: that account only ever comes from the environment seed
    if get_user_by_email(email) or (settings.ADMIN_EMAIL and email == settings.ADMIN_EMAIL):
        log_audit_event("AUTH_REGISTER_FAILURE", "FAILURE", actor=email, client_ip=client_ip, metadata={"reason": "email_unavailable"})
        return JSONResponse({"status": "error", "message": "An account with this email already exists. Sign in instead."}, status_code=400)

    # Registration never grants privileges
    pw_hash, salt = await run_in_threadpool(hash_password, password)
    user = create_user(email=email, password_hash=pw_hash, salt=salt, role="user")
    
    # Create persistent session
    session_token = create_session(user.id, expire_hours=settings.SESSION_EXPIRE_HOURS)
    log_audit_event("AUTH_REGISTER_SUCCESS", "SUCCESS", actor=user.email, client_ip=client_ip, target=str(user.id), metadata={"role": user.role})

    # Dispatch Discord Sign-Up Notification in background
    headers_dict = dict(request.headers)
    user_agent = headers_dict.get("user-agent", "")
    client_tool = identify_client_tool(user_agent)

    def _async_notify_signup(u: User, ip: str, ua: str, tool: str, hd: dict):
        try:
            geo = lookup_ip_geolocation(ip, headers=hd)
        except Exception:
            geo = {}
        send_discord_signup_alert(user=u, client_ip=ip, user_agent=ua, client_tool=tool, geo_data=geo)

    background_tasks.add_task(_async_notify_signup, user, client_ip, user_agent, client_tool, headers_dict)
    
    resp = JSONResponse({
        "status": "success",
        "message": "Operator account provisioned successfully",
        "user": user.model_dump(),
        "redirect": "/dashboard"
    })
    set_session_cookie(resp, request, session_token, settings.SESSION_EXPIRE_HOURS)
    return resp

@app.post("/api/auth/login")
async def api_login(data: UserLogin, request: Request):
    if not auth_configured():
        return JSONResponse(AUTH_UNAVAILABLE, status_code=503)
    client_ip, _ = extract_client_ip(request)
    email = data.email.strip().lower() if data.email else ""

    # 0. Brute-force limits: per client IP and per account (across all IPs)
    ip_locked, ip_remaining = login_limiter.is_locked(client_ip)
    acct_locked, acct_remaining = account_limiter.is_locked(email) if email else (False, 0)
    if ip_locked or acct_locked:
        log_audit_event("RATE_LIMIT_LOCKOUT", "BLOCKED", actor=email or "unknown", client_ip=client_ip,
                        metadata={"scope": "account" if acct_locked else "ip"})
        return too_many(max(ip_remaining, acct_remaining))

    # 1. Anti-bot honeypot check
    if data.hp_decoy_field:
        login_limiter.record_failure(client_ip)
        log_audit_event("AUTH_LOGIN_BOT_BLOCKED", "BLOCKED", actor=email or "unknown", client_ip=client_ip)
        return JSONResponse({"status": "error", "message": "Automated bot activity detected and blocked."}, status_code=403)

    # 2. CAPTCHA verification (single-use); failures count toward the IP limit
    if not check_captcha(data.captcha_answer, data.captcha_token):
        login_limiter.record_failure(client_ip)
        log_audit_event("AUTH_LOGIN_CAPTCHA_FAIL", "FAILURE", actor=email or "unknown", client_ip=client_ip)
        return JSONResponse({"status": "error", "message": "Security verification code is incorrect or expired. Please reload challenge."}, status_code=400)

    password = data.password or ""
    if not email or not password or len(password) > 256:
        log_audit_event("AUTH_LOGIN_FAILURE", "FAILURE", actor=email or "unknown", client_ip=client_ip, metadata={"reason": "missing_credentials"})
        return JSONResponse({"status": "error", "message": "Email and password required"}, status_code=400)

    # Same amount of work whether or not the account exists, off the event loop
    record = get_user_auth_record_by_email(email)
    if record:
        valid = await run_in_threadpool(verify_password, password, record["password_hash"], record["salt"])
    else:
        valid = await run_in_threadpool(burn_password_check, password)
    if not valid:
        login_limiter.record_failure(client_ip)
        account_limiter.record_failure(email)
        log_audit_event("AUTH_LOGIN_FAILURE", "FAILURE", actor=email, client_ip=client_ip)
        return JSONResponse({"status": "error", "message": "Invalid email or password."}, status_code=401)

    # Successful login: reset strikes
    login_limiter.record_success(client_ip)
    account_limiter.record_success(email)

    # Upgrade hashes made with the older work factor while we briefly know the password
    if needs_rehash(record["salt"]):
        new_hash, new_salt = await run_in_threadpool(hash_password, password)
        set_user_password(record["id"], new_hash, new_salt, must_change=bool(record.get("must_change_password")))

    user = User(
        id=record["id"],
        email=record["email"],
        role=record["role"],
        created_at=record["created_at"]
    )

    expire_hours = settings.SESSION_EXPIRE_HOURS if data.remember_me else 12
    session_token = create_session(user.id, expire_hours=expire_hours)
    log_audit_event("AUTH_LOGIN_SUCCESS", "SUCCESS", actor=user.email, client_ip=client_ip, target=str(user.id), metadata={"role": user.role})

    resp = JSONResponse({
        "status": "success",
        "message": "Identity authenticated",
        "user": user.model_dump(),
        "must_change_password": bool(record.get("must_change_password")),
        "redirect": "/dashboard"
    })
    set_session_cookie(resp, request, session_token, expire_hours)
    return resp

@app.post("/api/auth/logout")
async def api_logout(request: Request):
    client_ip, _ = extract_client_ip(request)
    user = get_current_user(request)
    session_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    auth_header = request.headers.get("authorization", "")
    if not session_token and auth_header.startswith("Bearer "):
        session_token = auth_header[7:].strip()
    if session_token:
        delete_session(session_token)
    log_audit_event("AUTH_LOGOUT", "SUCCESS", actor=user.email if user else "session", client_ip=client_ip)
    resp = JSONResponse({"status": "success", "message": "Session terminated", "redirect": "/login"})
    resp.delete_cookie(key=settings.SESSION_COOKIE_NAME)
    return resp

@app.post("/api/auth/logout-all")
async def api_logout_all(request: Request):
    """Ends every session of the current operator, including this one."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    client_ip, _ = extract_client_ip(request)
    ended = delete_user_sessions(user.id)
    log_audit_event("AUTH_LOGOUT_ALL", "SUCCESS", actor=user.email, client_ip=client_ip, target=user.id, metadata={"sessions_ended": ended})
    resp = JSONResponse({"status": "success", "message": f"Signed out of {ended} session(s).", "redirect": "/login"})
    resp.delete_cookie(key=settings.SESSION_COOKIE_NAME)
    return resp

@app.get("/api/auth/me")
async def api_me(request: Request):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"authenticated": False, "user": None}, status_code=401)
    record = get_user_auth_record_by_id(user.id)
    return {
        "authenticated": True,
        "user": user.model_dump(),
        "is_admin": user.is_admin,
        "must_change_password": bool(record and record.get("must_change_password")),
    }

def forgot_password_response() -> JSONResponse:
    return JSONResponse({
        "status": "success",
        "message": f"If an account uses that email, a reset link is on its way. It expires in {settings.PASSWORD_RESET_MINUTES} minutes."
    })

@app.post("/api/auth/forgot-password")
async def api_forgot_password(request: Request, data: Dict[str, Any], background_tasks: BackgroundTasks):
    """Emails a single-use reset link. The response is identical whether or not the account exists,
    and the email is sent in the background so timing doesn't reveal it either."""
    if not auth_configured():
        return JSONResponse(AUTH_UNAVAILABLE, status_code=503)
    client_ip, _ = extract_client_ip(request)
    locked, remaining = reset_ip_limiter.is_locked(client_ip)
    if locked:
        return too_many(remaining)
    reset_ip_limiter.record_failure(client_ip)

    if data.get("hp_decoy_field"):
        return forgot_password_response()
    if not check_captcha(data.get("captcha_answer"), data.get("captcha_token")):
        return JSONResponse({"status": "error", "message": "Security verification code is incorrect or expired. Please reload challenge."}, status_code=400)

    email = str(data.get("email") or "").strip().lower()[:254]
    if not email or not EMAIL_PATTERN.match(email):
        return forgot_password_response()
    # At most 3 emails per address per hour, silently: nobody can use this to flood an inbox
    if reset_email_limiter.is_locked(email)[0]:
        return forgot_password_response()
    reset_email_limiter.record_failure(email)

    record = get_user_auth_record_by_email(email)
    env_managed_admin = bool(settings.ADMIN_PASSWORD_HASH) and email == settings.ADMIN_EMAIL
    if record and not env_managed_admin:
        token = create_password_reset(record["id"], settings.PASSWORD_RESET_MINUTES)
        link = f"{settings.PUBLIC_URL}/reset-password#token={token}"
        background_tasks.add_task(send_password_reset_email, record["email"], link, settings.PASSWORD_RESET_MINUTES)
        log_audit_event("PASSWORD_RESET_REQUESTED", "SUCCESS", actor=record["email"], client_ip=client_ip, target=record["id"])
    else:
        log_audit_event("PASSWORD_RESET_REQUESTED", "NO_ELIGIBLE_ACCOUNT", actor=email, client_ip=client_ip)
    return forgot_password_response()

@app.post("/api/auth/reset-password")
async def api_reset_password(request: Request, data: Dict[str, Any]):
    """Completes a reset: the link's token is consumed once, the password replaced, every session ended."""
    if not auth_configured():
        return JSONResponse(AUTH_UNAVAILABLE, status_code=503)
    client_ip, _ = extract_client_ip(request)
    locked, remaining = login_limiter.is_locked(client_ip)
    if locked:
        return too_many(remaining)

    new_password = str(data.get("new_password") or "")
    if len(new_password) < 12 or len(new_password) > 256:
        return JSONResponse({"status": "error", "message": "Passwords must be 12 to 256 characters long."}, status_code=400)

    user_id = consume_password_reset(str(data.get("token") or ""))
    record = get_user_auth_record_by_id(user_id) if user_id else None
    if not record:
        login_limiter.record_failure(client_ip)
        return JSONResponse({"status": "error", "message": "This reset link is invalid, already used, or expired. Request a new one."}, status_code=400)

    pw_hash, salt = await run_in_threadpool(hash_password, new_password)
    set_user_password(record["id"], pw_hash, salt, must_change=False)
    ended = delete_user_sessions(record["id"])
    account_limiter.record_success(record["email"])
    log_audit_event("PASSWORD_RESET_COMPLETED", "SUCCESS", actor=record["email"], client_ip=client_ip, target=record["id"], metadata={"sessions_ended": ended})
    return {"status": "success", "message": "Password updated. Sign in with your new password.", "redirect": "/login"}

@app.post("/api/auth/change-password")
async def api_change_password(request: Request, data: Dict[str, Any]):
    """Any operator changes their own password; other sessions are signed out."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    client_ip, _ = extract_client_ip(request)
    locked, remaining = account_limiter.is_locked(user.email)
    if locked:
        return too_many(remaining)

    current = str(data.get("current_password") or "")
    new = str(data.get("new_password") or "")
    record = get_user_auth_record_by_id(user.id)
    if not record or not await run_in_threadpool(verify_password, current, record["password_hash"], record["salt"]):
        account_limiter.record_failure(user.email)
        log_audit_event("PASSWORD_CHANGE_FAILURE", "FAILURE", actor=user.email, client_ip=client_ip, metadata={"reason": "wrong_current_password"})
        return JSONResponse({"status": "error", "message": "Your current password is incorrect."}, status_code=400)
    if len(new) < 12 or len(new) > 256:
        return JSONResponse({"status": "error", "message": "Passwords must be 12 to 256 characters long."}, status_code=400)
    if new == current:
        return JSONResponse({"status": "error", "message": "Choose a password different from the current one."}, status_code=400)
    if user.is_admin and settings.ADMIN_PASSWORD_HASH and user.email == settings.ADMIN_EMAIL:
        return JSONResponse({"status": "error", "message": "The admin password is managed by ADMIN_PASSWORD_HASH. Generate a new one with `python cli.py hash-password`."}, status_code=400)

    pw_hash, salt = await run_in_threadpool(hash_password, new)
    set_user_password(user.id, pw_hash, salt, must_change=False)
    signed_out = delete_user_sessions(user.id, keep_token=session_token_from(request))
    account_limiter.record_success(user.email)
    log_audit_event("PASSWORD_CHANGED", "SUCCESS", actor=user.email, client_ip=client_ip, target=user.id, metadata={"other_sessions_ended": signed_out})
    return {"status": "success", "message": "Password changed. Other sessions were signed out."}

# -------------------------------------------------------------
# Admin: operator management
# -------------------------------------------------------------

@app.get("/api/admin/users")
async def api_admin_list_users(request: Request):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    if not user.is_admin:
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    return {"status": "success", "users": list_users()}

@app.post("/api/admin/users/{user_id}/reset-password")
async def api_admin_reset_password(user_id: str, request: Request):
    """Issues a one-time temporary password. The operator is signed out everywhere and must choose
    a new password at their next sign-in. The temporary password is returned once and never stored."""
    admin = get_current_user(request)
    if not admin:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    if not admin.is_admin:
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    client_ip, _ = extract_client_ip(request)

    target = get_user_auth_record_by_id(user_id)
    if not target:
        return JSONResponse({"status": "error", "message": "Operator not found."}, status_code=404)
    if target["id"] == admin.id or target["role"] == "admin":
        return JSONResponse({"status": "error", "message": "Admin passwords can't be reset here. Use ADMIN_PASSWORD_HASH for the admin account."}, status_code=400)

    temporary = "-".join(secrets.token_urlsafe(6) for _ in range(3))
    pw_hash, salt = await run_in_threadpool(hash_password, temporary)
    set_user_password(target["id"], pw_hash, salt, must_change=True)
    signed_out = delete_user_sessions(target["id"])
    account_limiter.record_success(target["email"])
    log_audit_event("ADMIN_PASSWORD_RESET", "SUCCESS", actor=admin.email, client_ip=client_ip, target=target["email"],
                    metadata={"sessions_ended": signed_out})
    return {
        "status": "success",
        "email": target["email"],
        "temporary_password": temporary,
        "message": f"Temporary password issued for {target['email']}. They must choose a new one when they sign in."
    }

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
        "safe_ips": list_safe_ips(owner_id=user.id, is_admin=user.is_admin),
        "client_ip": client_ip,
        "is_client_safe": is_safe_ip_for_owner(client_ip, user.id)
    }

@app.post("/api/safelist/add")
async def api_add_safelist(request: Request, data: Dict[str, Any]):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    
    client_ip, _ = extract_client_ip(request)
    ip = str(data.get("ip") or client_ip).strip()
    label = str(data.get("label") or "Operator workstation")[:120]

    success = add_safe_ip(ip, label=label, added_by=user.email, owner_id=user.id)
    log_audit_event("SAFELIST_ADD", "SUCCESS" if success else "FAILURE", actor=user.email, client_ip=client_ip, target=ip, metadata={"label": label})
    if success:
        return {"status": "success", "message": f"{ip} added to your safe list."}
    return JSONResponse({"status": "error", "message": "Enter a single valid IP address."}, status_code=400)

@app.post("/api/safelist/remove")
async def api_remove_safelist(request: Request, data: Dict[str, Any]):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    
    client_ip, _ = extract_client_ip(request)
    ip = data.get("ip")
    if not ip:
        return JSONResponse({"status": "error", "message": "IP required"}, status_code=400)
        
    removed = remove_safe_ip(str(ip), owner_id=user.id, is_admin=user.is_admin)
    log_audit_event("SAFELIST_REMOVE", "SUCCESS" if removed else "NOT_FOUND", actor=user.email, client_ip=client_ip, target=str(ip))
    if not removed:
        return JSONResponse({"status": "error", "removed": False, "message": "That address is not on your safe list."}, status_code=404)
    return {"status": "success", "removed": True, "message": f"{ip} removed from your safe list."}

@app.get("/api/stats")
async def api_stats(request: Request):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return get_dashboard_stats(user_id=user.id, is_admin=user.is_admin)

@app.get("/api/incidents")
async def api_incidents(request: Request, limit: int = 50, q: Optional[str] = None, min_score: Optional[int] = None):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    limit = max(1, min(limit, 500))
    incidents = list_incidents(user_id=user.id, is_admin=user.is_admin, limit=limit, q=q, min_score=min_score)
    return [i.model_dump() for i in incidents]

def build_threat_signals(incident: IncidentEvent, safelisted: bool) -> list:
    """Explains the threat score from the flags threat_intel already stored on the incident."""
    tool = incident.client_tool or "Unknown"
    is_browser = any(k in tool for k in ("Browser", "Firefox", "Safari"))
    return [
        {"key": "tor", "label": "Tor exit node", "active": bool(incident.is_tor)},
        {"key": "vpn", "label": "VPN / anonymizing proxy", "active": bool(incident.is_vpn_proxy)},
        {"key": "datacenter", "label": "Cloud datacenter / VPS range",
         "active": "datacenter" in (incident.connection_type or "").lower()},
        {"key": "scripted", "label": "Automated tooling" if is_browser else f"Automated tooling ({tool})", "active": not is_browser},
        {"key": "browser_probe", "label": "Browser hardware probe captured", "active": bool(incident.gpu_renderer or incident.screen_res)},
        {"key": "safelisted", "label": "Operator safe list", "active": safelisted},
    ]

@app.get("/api/incidents/{incident_id}")
async def api_incident_detail(request: Request, incident_id: int):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    incident = get_incident(incident_id, user_id=user.id, is_admin=user.is_admin)
    if not incident:
        return JSONResponse({"error": "Not found"}, status_code=404)
    timeline = list_incidents_by_ip(incident.attacker_ip, user_id=user.id, is_admin=user.is_admin)
    owner_token = get_token(incident.token_id)
    safelisted = is_safe_ip_for_owner(incident.attacker_ip, owner_token.owner_id if owner_token else None)
    tokens_touched = list(dict.fromkeys(i.token_id for i in timeline))
    return {
        "incident": incident.model_dump(),
        "timeline": [
            {"id": i.id, "timestamp": i.timestamp, "token_id": i.token_id, "threat_score": i.threat_score,
             "client_tool": i.client_tool, "http_method": i.http_method, "request_path": i.request_path}
            for i in timeline
        ],
        "summary": {
            "first_seen": timeline[0].timestamp if timeline else incident.timestamp,
            "last_seen": timeline[-1].timestamp if timeline else incident.timestamp,
            "hit_count": len(timeline),
            "tokens_touched": tokens_touched,
            "is_safelisted": safelisted,
        },
        "signals": build_threat_signals(incident, safelisted),
    }

@app.get("/api/audit-logs")
async def api_get_audit_logs(request: Request, limit: int = 50, action: Optional[str] = None):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    logs = list_audit_logs(limit=limit, action=action, actor=None if user.is_admin else user.email)
    return {"status": "success", "audit_logs": logs}

@app.get("/api/tokens")
async def api_tokens(request: Request):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    tokens = list_tokens(user_id=user.id, is_admin=user.is_admin)
    return [t.model_dump() for t in tokens]

DECOY_TYPES = {"web", "aws", "env", "git", "pdf", "keepass"}
MAX_DECOYS_PER_OPERATOR = 100
TRAPS_DIR = Path("traps")

def safe_file_stub(label: str) -> str:
    """A file-name-safe version of a decoy label: no separators, no dot-dot, bounded length."""
    stub = re.sub(r"[^A-Za-z0-9_-]+", "_", label).strip("_-")[:60]
    return stub or "decoy"

def trap_path(name: str) -> Path:
    """Resolves a path inside traps/ and refuses anything that escapes it."""
    base = TRAPS_DIR.resolve()
    target = (base / name).resolve()
    if base != target and base not in target.parents:
        raise ValueError("decoy path escapes the traps directory")
    return target

@app.post("/api/tokens/create")
async def api_create_token(request: Request, data: Dict[str, Any]):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    client_ip, _ = extract_client_ip(request)
    token_type = str(data.get("token_type") or "web")
    if token_type not in DECOY_TYPES:
        return JSONResponse({"status": "error", "message": "Unknown decoy type."}, status_code=400)
    label = str(data.get("label") or f"Decoy-{token_type.upper()}").strip()[:80] or f"Decoy-{token_type.upper()}"
    desc = str(data.get("description") or "Generated from Sentinel SOC Dashboard")[:200]
    if not user.is_admin and len(list_tokens(user_id=user.id, is_admin=False)) >= MAX_DECOYS_PER_OPERATOR:
        return JSONResponse({"status": "error", "message": f"Decoy limit reached ({MAX_DECOYS_PER_OPERATOR}). Remove unused decoys first."}, status_code=429)
    stub = safe_file_stub(label)

    if token_type == "web":
        token, _ = create_web_canary_token(label, desc, owner_id=user.id, owner_email=user.email)
    elif token_type == "aws":
        token, _ = create_aws_honeytoken(label, desc, owner_id=user.id, owner_email=user.email)
    elif token_type == "env":
        token, _ = create_env_honeytoken(label, desc, owner_id=user.id, owner_email=user.email)
    elif token_type == "git":
        token, _ = create_git_honeytoken(str(trap_path(f"git_decoy_{stub}")), label, owner_id=user.id, owner_email=user.email)
    elif token_type == "pdf":
        token, _ = create_canary_pdf(str(trap_path(f"{stub}.pdf")), label, owner_id=user.id, owner_email=user.email)
    elif token_type == "keepass":
        token, _ = create_keepass_honeytoken(str(trap_path(f"{stub}.kdbx")), label, owner_id=user.id, owner_email=user.email)
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
    ip = validate_containment_ip(data.get("ip"))
    if not ip:
        return JSONResponse({"status": "error", "applied": False, "message": "Only a single public IP address can be isolated."}, status_code=400)
    if ip == validate_containment_ip(client_ip):
        return JSONResponse({"status": "error", "applied": False, "message": "You can't isolate the address you're connected from."}, status_code=400)

    # Operators may only contain addresses that tripped their own decoys
    if not user.is_admin and not list_incidents_by_ip(ip, user_id=user.id, is_admin=False, limit=1):
        log_audit_event("CONTAINMENT_BLOCKED", "DENIED", actor=user.email, client_ip=client_ip, target=ip, metadata={"reason": "not_in_tenant_incidents"})
        return JSONResponse({"status": "error", "applied": False, "message": "You can only isolate addresses that tripped your own decoys."}, status_code=403)

    log_audit_event("CONTAINMENT_ATTEMPT", "ATTEMPT", actor=user.email, client_ip=client_ip, target=ip)

    # Operator Safety: Block isolation if IP is on any Safe List
    if is_safe_ip(ip):
        log_audit_event("CONTAINMENT_BLOCKED", "BLOCKED_SAFELIST", actor=user.email, client_ip=client_ip, target=ip, metadata={"reason": "safelist"})
        return JSONResponse({
            "status": "error",
            "applied": False,
            "message": f"{ip} is on an operator safe list, so it can't be isolated."
        }, status_code=400)

    result = block_ip(ip)
    log_audit_event("CONTAINMENT_RESULT", "SUCCESS" if result.get("applied") else "NO_OP", actor=user.email, client_ip=client_ip, target=ip, metadata=result)
    return {k: v for k, v in result.items() if k != "command"}

# -------------------------------------------------------------
# Deception & Honeytoken Listener Endpoints (PUBLIC CALLBACKS)
# -------------------------------------------------------------

TOKEN_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
# Built-in scanner traps that exist without a tokens row
BUILTIN_TRAP_IDS = {"canary_api_auth_trap", "scanner_env_probe"}
SPOOFABLE_GEO_HEADERS = ("x-vercel-ip-", "cf-ip")

def edge_headers_trusted(request: Request) -> bool:
    """Vercel's edge overwrites x-vercel-ip-*; cf-ip* is only believable from a Cloudflare peer."""
    if settings.IS_PRODUCTION:
        return True
    peer = request.client.host if request.client else ""
    return bool(peer) and ip_in_networks(peer, settings.get_cloudflare_proxies())
html_escape = html.escape

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
    # Unknown shapes get the same deceptive 401, with nothing reflected and nothing recorded
    if not TOKEN_ID_PATTERN.match(token_id):
        return JSONResponse(status_code=401, content={"error": "Unauthorized", "message": "Invalid token or expired session credential."})

    raw_ip, is_local = extract_client_ip(request)
    # Credentials a victim's browser sends (e.g. an operator's session cookie) are never stored
    headers_dict = redact_headers(dict(request.headers))
    geo_headers = headers_dict if edge_headers_trusted(request) else {
        k: v for k, v in headers_dict.items() if not k.startswith(SPOOFABLE_GEO_HEADERS)
    }

    # Record only real decoys, and at most 60 hits per source IP per 10 minutes. The response is the
    # same either way, so a flooder learns nothing, but the database and Discord stay usable.
    known_trap = token_id in BUILTIN_TRAP_IDS or get_token(token_id) is not None
    flooding = canary_limiter.is_locked(raw_ip)[0]
    user_agent = headers_dict.get("user-agent", "")
    client_tool = identify_client_tool(user_agent)
    
    # Enqueue heavy telemetry resolution, GeoIP, threat intel, and Discord alerting to background
    if known_trap and not flooding:
        canary_limiter.record_failure(raw_ip)
        background_tasks.add_task(
            process_incident_async,
            token_id=token_id,
            raw_ip=raw_ip,
            is_local=is_local,
            client_tool=client_tool,
            user_agent=user_agent[:512],
            http_method=request.method,
            request_path=str(request.url.path)[:512],
            query_params=str(request.url.query)[:2048],
            headers_dict=headers_dict,
            geo_headers=geo_headers
        )

    accept = headers_dict.get("accept", "")
    
    # 1. If requested by image / document or explicitly labeled as pdf/pixel
    if "image" in accept or request.query_params.get("source") == "pdf":
        return Response(content=TRANSPARENT_GIF_BYTES, media_type="image/gif")

    # 2. If requested by a human browser, serve deceptive corporate 401 page with silent hardware beacon
    if "text/html" in accept:
        template = get_template("decoy.html")
        if template:
            html = template.replace("{{ token_id_js }}", json.dumps(token_id)).replace("{{ token_id }}", html_escape(token_id))
            return HTMLResponse(content=html, status_code=401)

    # 3. For API or CLI tools (curl, python), return deceptive JSON error
    return JSONResponse(
        status_code=401,
        content={"error": "Unauthorized", "message": "Invalid token or expired session credential."}
    )

@app.post("/t/{token_id}/telemetry")
async def receive_browser_telemetry(
    token_id: str,
    telemetry: BrowserTelemetry,
    request: Request
):
    """Silent collector endpoint for client-side GPU, screen, and WebRTC LAN leaks."""
    if not TOKEN_ID_PATTERN.match(token_id):
        return {"status": "received"}
    client_ip, is_local = extract_client_ip(request)
    if telemetry_limiter.is_locked(client_ip)[0] or get_token(token_id) is None:
        return {"status": "received"}
    telemetry_limiter.record_failure(client_ip)
    update_incident_telemetry(token_id, telemetry, client_ip=client_ip, is_local=is_local)
    return {"status": "received"}

@app.api_route("/api/v1/auth/{path:path}", methods=["GET", "POST"])
async def decoy_auth_endpoint(path: str, request: Request, background_tasks: BackgroundTasks):
    return await trigger_canary("canary_api_auth_trap", request, background_tasks)

@app.api_route("/.env", methods=["GET"])
async def decoy_env_endpoint(request: Request, background_tasks: BackgroundTasks):
    return await trigger_canary("scanner_env_probe", request, background_tasks)
