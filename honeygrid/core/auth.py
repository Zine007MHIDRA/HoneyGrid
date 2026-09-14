import time
import random
import hashlib
import hmac
import secrets
from typing import Tuple

CAPTCHA_CHARS = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
CAPTCHA_COLORS = ["#f43f5e", "#06b6d4", "#10b981", "#f59e0b", "#a855f7", "#38bdf8"]

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

def generate_captcha(secret_key: str) -> Tuple[str, str, str]:
    """
    Generates a readable 5-character alphanumeric visual challenge
    as an inline dark-cyber SVG, along with a stateless HMAC signature token.
    """
    code = "".join(secrets.choice(CAPTCHA_CHARS) for _ in range(5))
    timestamp = int(time.time())
    salt = secrets.token_hex(8)
    
    # Cryptographic HMAC token
    msg = f"{code.upper()}:{timestamp}:{salt}".encode("utf-8")
    sig = hmac.new(secret_key.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    token = f"{timestamp}.{salt}.{sig}"
    
    elements = []
    # Background plate
    elements.append('<rect width="100%" height="100%" fill="#090d16" rx="10" stroke="#1c2438" stroke-width="1.5"/>')
    
    # Noise wave paths
    for _ in range(4):
        x1, y1 = random.randint(5, 35), random.randint(8, 42)
        qx, qy = random.randint(50, 130), random.randint(5, 45)
        x2, y2 = random.randint(145, 175), random.randint(8, 42)
        color = random.choice(["#1e293b", "#334155", "#475569"])
        dash = ' stroke-dasharray="4,4"' if random.random() > 0.5 else ''
        elements.append(f'<path d="M {x1} {y1} Q {qx} {qy} {x2} {y2}" stroke="{color}" stroke-width="1.5"{dash} fill="none"/>')
        
    # Noise dots
    for _ in range(25):
        cx, cy = random.randint(5, 175), random.randint(5, 45)
        r = random.uniform(1.0, 2.0)
        c = random.choice(["#334155", "#1e293b", "#f43f5e33", "#06b6d433"])
        elements.append(f'<circle cx="{cx}" cy="{cy}" r="{r:.1f}" fill="{c}"/>')
        
    # Characters with subtle jitter, rotation and vibrant neon tones
    x_positions = [22, 52, 82, 112, 142]
    for i, char in enumerate(code):
        x = x_positions[i] + random.randint(-2, 2)
        y = random.randint(31, 35)
        rot = random.randint(-14, 14)
        color = CAPTCHA_COLORS[i % len(CAPTCHA_COLORS)]
        elements.append(
            f'<text x="{x}" y="{y}" font-family="\'Geist Mono\', monospace, sans-serif" font-size="24" font-weight="800" '
            f'fill="{color}" transform="rotate({rot}, {x}, {y})" filter="drop-shadow(0px 0px 3px {color}88)">{char}</text>'
        )
        
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="180" height="48" viewBox="0 0 180 48">{"".join(elements)}</svg>'
    return code, svg, token

def verify_captcha(user_input: str, token: str, secret_key: str, max_age_seconds: int = 300) -> bool:
    """
    Verifies that the user entered code matches the stateless HMAC signature token
    and has not expired (default 5 minutes).
    """
    if not user_input or not token:
        return False
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False
        timestamp_str, salt, sig = parts
        timestamp = int(timestamp_str)
        
        # Check expiry (5 minutes) and clock skew
        now = time.time()
        if now - timestamp > max_age_seconds or now < timestamp - 15:
            return False
            
        clean_input = user_input.strip().upper().replace(" ", "")
        msg = f"{clean_input}:{timestamp}:{salt}".encode("utf-8")
        expected_sig = hmac.new(secret_key.encode("utf-8"), msg, hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected_sig)
    except Exception:
        return False

