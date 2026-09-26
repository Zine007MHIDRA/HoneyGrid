import math
import time
import random
import hashlib
import hmac
import secrets
from typing import Tuple

CAPTCHA_CHARS = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

# Stroke outlines on a 10x14 grid (y grows downward). Characters are drawn as paths so the
# answer never appears as text in the SVG markup.
CAPTCHA_GLYPHS = {
    "2": [[(0, 3), (1, 1), (3, 0), (7, 0), (9, 1), (10, 3), (10, 5), (8, 7), (0, 14), (10, 14)]],
    "3": [[(0, 1), (3, 0), (7, 0), (10, 2), (10, 5), (7, 7), (3, 7)], [(7, 7), (10, 9), (10, 12), (7, 14), (3, 14), (0, 13)]],
    "4": [[(8, 14), (8, 0), (0, 10), (10, 10)]],
    "5": [[(10, 0), (1, 0), (0, 6), (6, 6), (9, 7), (10, 10), (9, 13), (6, 14), (0, 14)]],
    "6": [[(9, 1), (6, 0), (3, 0), (1, 2), (0, 6), (0, 11), (2, 14), (8, 14), (10, 12), (10, 9), (8, 7), (2, 7), (0, 9)]],
    "7": [[(0, 0), (10, 0), (4, 14)]],
    "8": [[(5, 7), (1, 5), (1, 2), (3, 0), (7, 0), (9, 2), (9, 5), (5, 7), (0, 10), (0, 12), (2, 14), (8, 14), (10, 12), (10, 10), (5, 7)]],
    "9": [[(10, 5), (8, 7), (2, 7), (0, 5), (0, 2), (2, 0), (8, 0), (10, 2), (10, 8), (9, 12), (7, 14), (3, 14), (1, 13)]],
    "A": [[(0, 14), (5, 0), (10, 14)], [(2, 9), (8, 9)]],
    "B": [[(0, 0), (0, 14), (7, 14), (10, 12), (10, 9), (7, 7), (0, 7)], [(0, 0), (6, 0), (9, 2), (9, 5), (6, 7)]],
    "C": [[(10, 2), (8, 0), (3, 0), (0, 3), (0, 11), (3, 14), (8, 14), (10, 12)]],
    "D": [[(0, 0), (0, 14), (6, 14), (10, 10), (10, 4), (6, 0), (0, 0)]],
    "E": [[(10, 0), (0, 0), (0, 14), (10, 14)], [(0, 7), (7, 7)]],
    "F": [[(10, 0), (0, 0), (0, 14)], [(0, 7), (7, 7)]],
    "G": [[(10, 2), (8, 0), (3, 0), (0, 3), (0, 11), (3, 14), (8, 14), (10, 12), (10, 8), (6, 8)]],
    "H": [[(0, 0), (0, 14)], [(10, 0), (10, 14)], [(0, 7), (10, 7)]],
    "J": [[(10, 0), (10, 11), (7, 14), (3, 14), (0, 11)]],
    "K": [[(0, 0), (0, 14)], [(10, 0), (0, 8)], [(3, 6), (10, 14)]],
    "M": [[(0, 14), (0, 0), (5, 8), (10, 0), (10, 14)]],
    "N": [[(0, 14), (0, 0), (10, 14), (10, 0)]],
    "P": [[(0, 14), (0, 0), (7, 0), (10, 2), (10, 5), (7, 7), (0, 7)]],
    "Q": [[(3, 0), (7, 0), (10, 3), (10, 11), (7, 14), (3, 14), (0, 11), (0, 3), (3, 0)], [(6, 10), (10, 15)]],
    "R": [[(0, 14), (0, 0), (7, 0), (10, 2), (10, 5), (7, 7), (0, 7)], [(5, 7), (10, 14)]],
    "S": [[(10, 2), (8, 0), (2, 0), (0, 2), (0, 5), (2, 7), (8, 7), (10, 9), (10, 12), (8, 14), (2, 14), (0, 12)]],
    "T": [[(0, 0), (10, 0)], [(5, 0), (5, 14)]],
    "U": [[(0, 0), (0, 11), (3, 14), (7, 14), (10, 11), (10, 0)]],
    "V": [[(0, 0), (5, 14), (10, 0)]],
    "W": [[(0, 0), (2, 14), (5, 6), (8, 14), (10, 0)]],
    "X": [[(0, 0), (10, 14)], [(10, 0), (0, 14)]],
    "Y": [[(0, 0), (5, 7), (10, 0)], [(5, 7), (5, 14)]],
    "Z": [[(0, 0), (10, 0), (0, 14), (10, 14)]],
}

def _glyph_path(char: str, ox: float, oy: float, scale: float, angle_deg: float) -> str:
    """Projects a glyph's strokes with rotation, scale and per-point jitter into one SVG path."""
    rad = math.radians(angle_deg)
    cos_a, sin_a = math.cos(rad), math.sin(rad)
    parts = []
    for stroke in CAPTCHA_GLYPHS[char]:
        cmds = []
        for i, (gx, gy) in enumerate(stroke):
            jx = gx + random.uniform(-0.45, 0.45) - 5
            jy = gy + random.uniform(-0.45, 0.45) - 7
            x = ox + (jx * cos_a - jy * sin_a) * scale
            y = oy + (jx * sin_a + jy * cos_a) * scale
            cmds.append(f"{'M' if i == 0 else 'L'}{x:.1f} {y:.1f}")
        parts.append(" ".join(cmds))
    return " ".join(parts)

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

def encode_password_hash(password: str) -> str:
    """Single-string form used for ADMIN_PASSWORD_HASH: pbkdf2_sha256$<salt>$<hex hash>."""
    pw_hash, salt = hash_password(password)
    return f"pbkdf2_sha256${salt}${pw_hash}"

def decode_password_hash(encoded: str) -> Tuple[str, str]:
    """Returns (hash, salt) from encode_password_hash output; raises ValueError when malformed."""
    scheme, salt, pw_hash = encoded.strip().split("$")
    if scheme != "pbkdf2_sha256" or not salt or len(pw_hash) != 64:
        raise ValueError("ADMIN_PASSWORD_HASH must look like pbkdf2_sha256$<salt>$<64 hex chars>")
    return pw_hash, salt

_DUMMY_SALT = secrets.token_hex(16)
_DUMMY_HASH = hashlib.pbkdf2_hmac("sha256", secrets.token_bytes(16), _DUMMY_SALT.encode("utf-8"), 200_000).hex()

def burn_password_check(password: str) -> bool:
    """Spends the same work as a real verification so unknown emails can't be told apart by timing."""
    verify_password(password or "", _DUMMY_HASH, _DUMMY_SALT)
    return False

def captcha_signature(token: str) -> str:
    """The HMAC part of a captcha token, used to make each token single-use."""
    parts = (token or "").split(".")
    return parts[2] if len(parts) == 3 else ""

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
    elements.append('<rect width="100%" height="100%" fill="none"/>')
    
    # Noise wave paths
    for _ in range(4):
        x1, y1 = random.randint(5, 35), random.randint(8, 42)
        qx, qy = random.randint(50, 130), random.randint(5, 45)
        x2, y2 = random.randint(145, 175), random.randint(8, 42)
        color = "currentColor"
        dash = ' stroke-dasharray="4,4"' if random.random() > 0.5 else ''
        elements.append(f'<path d="M {x1} {y1} Q {qx} {qy} {x2} {y2}" stroke="{color}" stroke-opacity="0.35" stroke-width="1.5"{dash} fill="none"/>')
        
    # Noise dots
    for _ in range(25):
        cx, cy = random.randint(5, 175), random.randint(5, 45)
        r = random.uniform(1.0, 2.0)
        elements.append(f'<circle cx="{cx}" cy="{cy}" r="{r:.1f}" fill="currentColor" fill-opacity="0.25"/>')
        
    # Characters as jittered stroke paths: nothing in the markup spells the answer
    x_positions = [24, 56, 88, 120, 152]
    for i, char in enumerate(code):
        cx = x_positions[i] + random.uniform(-2.5, 2.5)
        cy = 24 + random.uniform(-2.5, 2.5)
        scale = random.uniform(1.55, 1.8)
        angle = random.uniform(-13, 13)
        d = _glyph_path(char, cx, cy, scale, angle)
        width = random.uniform(2.3, 2.9)
        elements.append(
            f'<path d="{d}" fill="none" stroke="currentColor" stroke-width="{width:.1f}" '
            f'stroke-linecap="round" stroke-linejoin="round"/>'
        )
    # Shuffle draw order so the markup order doesn't spell the answer either
    body = elements[1:]
    random.shuffle(body)
    elements = elements[:1] + body
        
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

