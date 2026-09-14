import os
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
    HONEYGRID_HOST: str = os.getenv("HONEYGRID_HOST", "0.0.0.0").strip() or "0.0.0.0"
    HONEYGRID_PORT: int = _get_int("HONEYGRID_PORT", 8000)
    HONEYGRID_BASE_URL: str = _get_base_url()
    HONEYGRID_DB_PATH: str = os.getenv("HONEYGRID_DB_PATH", str(BASE_DIR / "honeygrid.db")).strip() or str(BASE_DIR / "honeygrid.db")
    ENABLE_GEOIP_LOOKUP: bool = os.getenv("ENABLE_GEOIP_LOOKUP", "true").strip().lower() in ("true", "1", "yes")
    ADMIN_EMAIL: str = os.getenv("ADMIN_EMAIL", "zine.mhidra@gmail.com").strip().lower()
    HONEYGRID_SECRET_KEY: str = os.getenv("HONEYGRID_SECRET_KEY", "hg-sentinel-master-secret-key-392810").strip()
    SESSION_COOKIE_NAME: str = "honeygrid_session"
    SESSION_EXPIRE_HOURS: int = _get_int("SESSION_EXPIRE_HOURS", 168)  # 7 days

settings = Settings()
