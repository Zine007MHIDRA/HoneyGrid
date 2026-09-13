import os
from pathlib import Path
from dotenv import load_dotenv

# Locate and load .env file
BASE_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = BASE_DIR / ".env"
load_dotenv(dotenv_path=ENV_PATH)

class Settings:
    DISCORD_WEBHOOK_URL: str = os.getenv("DISCORD_WEBHOOK_URL", "")
    HONEYGRID_HOST: str = os.getenv("HONEYGRID_HOST", "0.0.0.0")
    HONEYGRID_PORT: int = int(os.getenv("HONEYGRID_PORT", "8000"))
    HONEYGRID_BASE_URL: str = os.getenv("HONEYGRID_BASE_URL", "http://localhost:8000").rstrip("/")
    HONEYGRID_DB_PATH: str = os.getenv("HONEYGRID_DB_PATH", str(BASE_DIR / "honeygrid.db"))
    ENABLE_GEOIP_LOOKUP: bool = os.getenv("ENABLE_GEOIP_LOOKUP", "true").lower() in ("true", "1", "yes")

settings = Settings()
