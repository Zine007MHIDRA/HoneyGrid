import hashlib
import hmac
import secrets
from typing import Tuple

def hash_password(password: str, salt: str = None) -> Tuple[str, str]:
    """
    Hashes a password using PBKDF2-HMAC-SHA256 with 200,000 iterations
    and a cryptographically secure 16-byte random salt.
    """
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        200_000
    )
    return key.hex(), salt

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """
    Verifies a password against the stored hash and salt using constant-time comparison.
    """
    calculated_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(calculated_hash, stored_hash)

def generate_session_token() -> str:
    """Generates a URL-safe, high-entropy 32-byte session token."""
    return f"hgs_{secrets.token_urlsafe(32)}"

def generate_user_id() -> str:
    """Generates a realistic, collision-resistant user ID."""
    return f"usr_{secrets.token_hex(8)}"
