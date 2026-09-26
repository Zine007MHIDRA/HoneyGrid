import threading
from typing import Tuple
from honeygrid.database import db_is_locked, db_record_failure, db_record_success

class LoginRateLimiter:
    """
    Persistent, thread-safe sliding window rate limiter backed by SQLite.
    Survives application restarts on the same database. Keys are opaque strings:
    a client IP, or a prefixed key such as "acct:<email>" for per-account limits.
    No key is exempt: a safe-listed IP must not become a license to brute-force.
    """
    def __init__(self, max_attempts: int = 5, window_seconds: int = 600, lockout_seconds: int = 600, prefix: str = ""):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self.prefix = prefix
        self._lock = threading.Lock()

    def _key(self, key: str) -> str:
        clean = (key or "").strip().lower() if self.prefix else (key or "").strip()
        return f"{self.prefix}{clean}" if clean else ""

    def is_locked(self, key: str) -> Tuple[bool, int]:
        """Returns (is_locked, remaining_seconds)."""
        k = self._key(key)
        if not k:
            return False, 0
        with self._lock:
            return db_is_locked(
                k,
                window_seconds=self.window_seconds,
                max_attempts=self.max_attempts,
                lockout_seconds=self.lockout_seconds
            )

    def record_failure(self, key: str) -> int:
        """Records a failed (or, for request limits, any) attempt and returns recent attempts."""
        k = self._key(key)
        if not k:
            return 0
        with self._lock:
            return db_record_failure(
                k,
                window_seconds=self.window_seconds,
                max_attempts=self.max_attempts,
                lockout_seconds=self.lockout_seconds
            )

    def record_success(self, key: str):
        """Clears recorded attempts for the key upon successful authentication."""
        k = self._key(key)
        if not k:
            return
        with self._lock:
            db_record_success(k)

# Per client IP: failed logins, bot-trap hits and bad captchas
login_limiter = LoginRateLimiter(max_attempts=5, window_seconds=600, lockout_seconds=600)
# Per account, across all IPs: stops distributed guessing against one email
account_limiter = LoginRateLimiter(max_attempts=10, window_seconds=900, lockout_seconds=900, prefix="acct:")
# Per client IP: every registration attempt counts
register_limiter = LoginRateLimiter(max_attempts=5, window_seconds=3600, lockout_seconds=3600, prefix="reg:")
# Per client IP: captcha issuance
captcha_limiter = LoginRateLimiter(max_attempts=40, window_seconds=600, lockout_seconds=600, prefix="cap:")
# Per source IP: canary hits that get recorded (the decoy response itself is never throttled)
canary_limiter = LoginRateLimiter(max_attempts=60, window_seconds=600, lockout_seconds=600, prefix="can:")
# Per source IP: browser telemetry submissions
telemetry_limiter = LoginRateLimiter(max_attempts=30, window_seconds=600, lockout_seconds=600, prefix="tel:")
# Per attacker+decoy: at most one Discord alert every 5 minutes
alert_limiter = LoginRateLimiter(max_attempts=1, window_seconds=300, lockout_seconds=300, prefix="alert:")
