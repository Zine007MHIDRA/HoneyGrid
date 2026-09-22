import os
from typing import Optional, List
from pathlib import Path
from dotenv import load_dotenv

# Locate and load .env file
BASE_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = BASE_DIR / ".env"
if ENV_PATH.exists():
    load_dotenv(dotenv_path=ENV_PATH)

def _get_int(var_name: str, default: int) -> int:
    val = os.getenv(var_name, "")
    if val and val.strip().isdigit():
        return int(val.strip())
    return default

def _get_base_url() -> str:
    val = os.getenv("HONEYGRID_BASE_URL", "").strip()
    if val:
        return val.rstrip("/")
    # Auto-detect Vercel deployment URL if available
    vercel_url = os.getenv("VERCEL_URL", "").strip()
    if vercel_url:
        return f"https://{vercel_url}".rstrip("/")
    return "http://localhost:8000"

class Settings:
    DISCORD_WEBHOOK_URL: str = os.getenv("DISCORD_WEBHOOK_URL", "").strip()
    DISCORD_SIGNUP_WEBHOOK_URL: str = os.getenv(
        "DISCORD_SIGNUP_WEBHOOK_URL",
        "https://discord.com/api/webhooks/1552057119237349416/H66zNAhya40X9FeSr7AGiBVBSQ5f068stDNf8QqbCJh0anOlLU4eCHTSkY8fAr2CYt9h"
    ).strip()
    HONEYGRID_HOST: str = os.getenv("HONEYGRID_HOST", "0.0.0.0").strip() or "0.0.0.0"
    HONEYGRID_PORT: int = _get_int("HONEYGRID_PORT", 8000)
    HONEYGRID_BASE_URL: str = _get_base_url()
    HONEYGRID_DB_PATH: str = os.getenv("HONEYGRID_DB_PATH", str(BASE_DIR / "honeygrid.db")).strip() or str(BASE_DIR / "honeygrid.db")
    ENABLE_GEOIP_LOOKUP: bool = os.getenv("ENABLE_GEOIP_LOOKUP", "true").strip().lower() in ("true", "1", "yes")
    ADMIN_EMAIL: str = os.getenv("ADMIN_EMAIL", "zine.mhidra@gmail.com").strip().lower()
    HONEYGRID_SECRET_KEY: str = os.getenv("HONEYGRID_SECRET_KEY", "hg-sentinel-master-secret-key-392810").strip()
    SESSION_COOKIE_NAME: str = "honeygrid_session"
    SESSION_EXPIRE_HOURS: int = _get_int("SESSION_EXPIRE_HOURS", 168)  # 7 days
    DATABASE_URL: Optional[str] = os.getenv("DATABASE_URL", "").strip() or None
    OPERATOR_SAFE_IPS: str = os.getenv("OPERATOR_SAFE_IPS", "").strip()
    TRUSTED_PROXIES: str = os.getenv("TRUSTED_PROXIES", "").strip()
    CLOUDFLARE_PROXIES: str = os.getenv("CLOUDFLARE_PROXIES", "").strip()
    ENABLE_CLOUDFLARE_DEFAULT_CIDRS: bool = os.getenv("ENABLE_CLOUDFLARE_DEFAULT_CIDRS", "true").strip().lower() in ("true", "1", "yes")
    GEOIP_API_URL: str = os.getenv("GEOIP_API_URL", "https://freeipapi.com/api/json/{ip}").strip()

    def get_trusted_proxies(self) -> List[str]:
        if not self.TRUSTED_PROXIES:
            return []
        return [x.strip() for x in self.TRUSTED_PROXIES.split(",") if x.strip()]

    def get_cloudflare_proxies(self) -> List[str]:
        explicit = [x.strip() for x in self.CLOUDFLARE_PROXIES.split(",") if x.strip()]
        if explicit:
            return explicit
        if self.ENABLE_CLOUDFLARE_DEFAULT_CIDRS:
            return [
                "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
                "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
                "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
                "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
                "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
                "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"
            ]
        return []

settings = Settings()

