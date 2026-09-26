from typing import Dict, Optional

# Header values that carry credentials. They must never be stored with an incident:
# a victim who follows a canary link on this origin would otherwise hand their session
# cookie to whoever owns the canary.
CREDENTIAL_HEADERS = {
    "cookie",
    "set-cookie",
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
}

def _cookie_names(value: str) -> str:
    names = [part.split("=", 1)[0].strip() for part in value.split(";") if part.strip()]
    return ", ".join(n for n in names if n)[:200]

def redact_headers(headers: Optional[Dict[str, str]]) -> Dict[str, str]:
    """Returns a copy of request headers with credential values removed but their shape kept for forensics."""
    if not headers:
        return {}
    clean = {}
    for key, value in headers.items():
        k = str(key).lower()
        v = "" if value is None else str(value)
        if k not in CREDENTIAL_HEADERS:
            clean[k] = v
        elif k in ("cookie", "set-cookie"):
            clean[k] = f"[redacted: {_cookie_names(v)}]"
        elif k in ("authorization", "proxy-authorization"):
            scheme = v.split(" ", 1)[0][:20] if v else ""
            clean[k] = f"[redacted: {scheme} credential]" if scheme else "[redacted]"
        else:
            clean[k] = "[redacted]"
    return clean

def headers_need_redaction(headers: Optional[Dict[str, str]]) -> bool:
    if not headers:
        return False
    for key, value in headers.items():
        if str(key).lower() in CREDENTIAL_HEADERS and not str(value).startswith("[redacted"):
            return True
    return False
