import uuid
import secrets
import string
import io
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
from honeygrid.config import settings
from honeygrid.models import Token
from honeygrid.database import save_token

def generate_unique_token_id(prefix: str = "hg") -> str:
    """Generates a URL-safe, realistic token identifier."""
    rand_chars = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(12))
    return f"{prefix}_{rand_chars}"

def create_web_canary_token(label: str, description: str = "", owner_id: Optional[str] = None, owner_email: Optional[str] = None) -> Tuple[Token, str]:
    """Generates an HTTP canary link."""
    token_id = generate_unique_token_id("canary")
    canary_url = f"{settings.HONEYGRID_BASE_URL}/t/{token_id}"
    
    token = Token(
        id=token_id,
        token_type="web",
        label=label,
        description=description or f"Web canary URL: {canary_url}",
        created_at=datetime.now(timezone.utc).isoformat(),
        owner_id=owner_id,
        owner_email=owner_email,
        metadata={"canary_url": canary_url}
    )
    save_token(token)
    return token, canary_url

def create_aws_honeytoken(label: str, description: str = "", owner_id: Optional[str] = None, owner_email: Optional[str] = None) -> Tuple[Token, Dict[str, str]]:
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
        owner_id=owner_id,
        owner_email=owner_email,
        metadata={
            "access_key_id": access_key_id,
            "canary_url": canary_url,
            "raw_content": credentials_content
        }
    )
    save_token(token)
    return token, {"access_key_id": access_key_id, "secret_key": secret_key, "file_content": credentials_content, "canary_url": canary_url}

def create_env_honeytoken(label: str, description: str = "", owner_id: Optional[str] = None, owner_email: Optional[str] = None) -> Tuple[Token, str]:
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
        owner_id=owner_id,
        owner_email=owner_email,
        metadata={"canary_url": canary_url, "file_content": env_content}
    )
    save_token(token)
    return token, env_content

def create_honeyfile_tripwire(filepath: str, label: str, description: str = "", owner_id: Optional[str] = None, owner_email: Optional[str] = None) -> Token:
    """Registers a filesystem file path as a tripwire to be monitored by the file watcher."""
    token_id = generate_unique_token_id("file")
    resolved_path = str(Path(filepath).resolve())
    
    token = Token(
        id=token_id,
        token_type="honeyfile",
        label=label,
        description=description or f"Honeyfile Tripwire at {resolved_path}",
        created_at=datetime.now(timezone.utc).isoformat(),
        owner_id=owner_id,
        owner_email=owner_email,
        metadata={"target_path": resolved_path}
    )
    save_token(token)
    return token

def create_git_honeytoken(target_dir: str, label: str = "Internal-Git-Decoy", owner_id: Optional[str] = None, owner_email: Optional[str] = None) -> Tuple[Token, str]:
    """
    Generates a decoy Git repository containing a canary remote URL in .git/config.
    When an attacker enters the repo and runs 'git pull' or 'git fetch', the canary trips.
    """
    token_id = generate_unique_token_id("git")
    canary_url = f"{settings.HONEYGRID_BASE_URL}/t/{token_id}?source=git_fetch"
    
    repo_path = Path(target_dir)
    git_dir = repo_path / ".git"
    git_dir.mkdir(parents=True, exist_ok=True)
    
    git_config_content = f"""[core]
\trepositoryformatversion = 0
\tfilemode = false
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = {canary_url}
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""
    with open(git_dir / "config", "w") as f:
        f.write(git_config_content)
        
    with open(repo_path / "README.md", "w") as f:
        f.write("# Internal Infrastructure Automation & Deployment Scripts\nCONFIDENTIAL - Property of Corporate DevSecOps.\n")
        
    token = Token(
        id=token_id,
        token_type="git_repo",
        label=label,
        description=f"Decoy Git repository at {repo_path.resolve()}",
        created_at=datetime.now(timezone.utc).isoformat(),
        owner_id=owner_id,
        owner_email=owner_email,
        metadata={"canary_url": canary_url, "repo_path": str(repo_path.resolve())}
    )
    save_token(token)
    return token, canary_url

def create_keepass_honeytoken(output_path: str, label: str = "Corporate-KeePass-Vault", owner_id: Optional[str] = None, owner_email: Optional[str] = None) -> Tuple[Token, str]:
    """
    Generates an authentic-looking KeePass 2.x (.kdbx) password vault database.
    Registers the path with the honeyfile tripwire monitor.
    """
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    
    # KeePass 2.x KDBX File Header Magic Bytes: 0x9AA2D903, 0xB54BFB67
    kdbx_signature = b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5\x00\x00\x04\x00"
    # Seed plausible random binary structure
    pseudo_encrypted_data = secrets.token_bytes(4096)
    
    with open(out_file, "wb") as f:
        f.write(kdbx_signature + pseudo_encrypted_data)
        
    token = create_honeyfile_tripwire(
        str(out_file),
        label=label,
        description=f"Decoy KeePass Database Vault at {out_file.resolve()}",
        owner_id=owner_id,
        owner_email=owner_email
    )
    return token, str(out_file.resolve())


def generate_token_download_payload(token: Token) -> Tuple[bytes, str, str]:
    """
    Returns (bytes_content, filename, mime_type) for dynamic file download
    of any deception asset.
    """
    token_type = token.token_type.lower()
    clean_label = "".join(c for c in token.label if c.isalnum() or c in ("-", "_")).strip() or "honeytoken"
    canary_url = token.metadata.get("canary_url", f"{settings.HONEYGRID_BASE_URL}/t/{token.id}")
    
    if token_type in ("canary_pdf", "pdf"):
        from honeygrid.core.pdf_canary import generate_canary_pdf_bytes
        pdf_bytes = generate_canary_pdf_bytes(token.id, token.label)
        filename = f"{clean_label}.pdf"
        return pdf_bytes, filename, "application/pdf"
        
    elif token_type in ("aws", "aws_key"):
        content = token.metadata.get("raw_content")
        if not content:
            access_key_id = token.metadata.get("access_key_id", f"AKIA{secrets.token_hex(8).upper()}")
            content = f"""[default]
aws_access_key_id = {access_key_id}
aws_secret_access_key = {secrets.token_urlsafe(30)}
# Verify internal auth gateway: {canary_url}
region = us-east-1
"""
        return content.encode("utf-8"), "credentials", "text/plain"
        
    elif token_type in ("env", "env_file"):
        content = token.metadata.get("file_content")
        if not content:
            content = f"""# Production Environment Secrets - Internal Confidential
NODE_ENV=production
PORT=443
DATABASE_URL=postgres://admin_user:{secrets.token_hex(12)}@db.internal.corp:5432/primary_prod
INTERNAL_API_SYNC_URL={canary_url}
STRIPE_SECRET_KEY=sk_live_{secrets.token_urlsafe(24)}
GITHUB_ENTERPRISE_TOKEN=ghp_{secrets.token_urlsafe(32)}
"""
        return content.encode("utf-8"), ".env", "text/plain"
        
    elif token_type in ("git", "git_repo"):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            git_config = f"""[core]
\trepositoryformatversion = 0
\tfilemode = false
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = {canary_url}
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""
            zf.writestr(".git/config", git_config)
            zf.writestr("README.md", "# Internal Automation Scripts\nCONFIDENTIAL - Property of Corporate DevSecOps.\n")
        return buf.getvalue(), f"{clean_label}-git-repo.zip", "application/zip"
        
    elif token_type in ("keepass", "honeyfile"):
        kdbx_signature = b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5\x00\x00\x04\x00"
        pseudo_data = secrets.token_bytes(4096)
        filename = f"{clean_label}.kdbx" if not clean_label.endswith(".kdbx") else clean_label
        return kdbx_signature + pseudo_data, filename, "application/octet-stream"
        
    else:  # web or generic canary
        shortcut = f"""[InternetShortcut]
URL={canary_url}
Comment=Corporate Verification Portal
"""
        return shortcut.encode("utf-8"), f"{clean_label}-shortcut.url", "text/plain"


