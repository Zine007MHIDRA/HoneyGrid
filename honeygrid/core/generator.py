import uuid
import secrets
import string
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple
from honeygrid.config import settings
from honeygrid.models import Token
from honeygrid.database import save_token

def generate_unique_token_id(prefix: str = "hg") -> str:
    """Generates a URL-safe, realistic token identifier."""
    rand_chars = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(12))
    return f"{prefix}_{rand_chars}"

def create_web_canary_token(label: str, description: str = "") -> Tuple[Token, str]:
    """Generates an HTTP canary link."""
    token_id = generate_unique_token_id("canary")
    canary_url = f"{settings.HONEYGRID_BASE_URL}/t/{token_id}"
    
    token = Token(
        id=token_id,
        token_type="web",
        label=label,
        description=description or f"Web canary URL: {canary_url}",
        created_at=datetime.now(timezone.utc).isoformat(),
        metadata={"canary_url": canary_url}
    )
    save_token(token)
    return token, canary_url

def create_aws_honeytoken(label: str, description: str = "") -> Tuple[Token, Dict[str, str]]:
    """
    Generates a realistic AWS IAM decoy credential set.
    The secret key is encoded with a canary trigger URL or callback endpoint.
    """
    token_id = generate_unique_token_id("aws")
    # Generate realistic AWS Access Key ID starting with AKIA
    random_suffix = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    access_key_id = f"AKIA{random_suffix}"
    
    # Secret access key
    secret_key = secrets.token_urlsafe(30)
    canary_url = f"{settings.HONEYGRID_BASE_URL}/t/{token_id}"
    
    credentials_content = f"""[default]
aws_access_key_id = {access_key_id}
aws_secret_access_key = {secret_key}
# Verify at internal auth gateway: {canary_url}
region = us-east-1
"""
    token = Token(
        id=token_id,
        token_type="aws_key",
        label=label,
        description=description or "Decoy AWS IAM Access Key",
        created_at=datetime.now(timezone.utc).isoformat(),
        metadata={
            "access_key_id": access_key_id,
            "canary_url": canary_url,
            "raw_content": credentials_content
        }
    )
    save_token(token)
    return token, {"access_key_id": access_key_id, "secret_key": secret_key, "file_content": credentials_content, "canary_url": canary_url}

def create_env_honeytoken(label: str, description: str = "") -> Tuple[Token, str]:
    """Generates a realistic decoy .env file with multiple canary-infused keys."""
    token_id = generate_unique_token_id("env")
    canary_url = f"{settings.HONEYGRID_BASE_URL}/t/{token_id}"
    
    env_content = f"""# Production Environment Secrets - DO NOT SHARE
NODE_ENV=production
PORT=443
DATABASE_URL=postgres://admin_user:{secrets.token_hex(12)}@db.internal.corp:5432/primary_prod
INTERNAL_API_SYNC_URL={canary_url}
STRIPE_SECRET_KEY=sk_live_{secrets.token_urlsafe(24)}
GITHUB_ENTERPRISE_TOKEN=ghp_{secrets.token_urlsafe(32)}
"""
    token = Token(
        id=token_id,
        token_type="env_file",
        label=label,
        description=description or "Decoy .env file with sensitive credentials and canary sync URL",
        created_at=datetime.now(timezone.utc).isoformat(),
        metadata={"canary_url": canary_url, "file_content": env_content}
    )
    save_token(token)
    return token, env_content

def create_honeyfile_tripwire(filepath: str, label: str, description: str = "") -> Token:
    """Registers a filesystem file path as a tripwire to be monitored by the file watcher."""
    token_id = generate_unique_token_id("file")
    resolved_path = str(Path(filepath).resolve())
    
    token = Token(
        id=token_id,
        token_type="honeyfile",
        label=label,
        description=description or f"Honeyfile Tripwire at {resolved_path}",
        created_at=datetime.now(timezone.utc).isoformat(),
        metadata={"target_path": resolved_path}
    )
    save_token(token)
    return token
