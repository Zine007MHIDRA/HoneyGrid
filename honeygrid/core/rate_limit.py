import time
import threading
from typing import Tuple
from honeygrid.database import db_is_locked, db_record_failure, db_record_success, is_safe_ip

class LoginRateLimiter:
    """
    Persistent, thread-safe sliding window rate limiter backed by SQLite.
    Survives application restarts and multi-worker deployment.
    Exempts Operator Safe-Listed IPs from accidental lockouts.
    """
    def __init__(self, max_attempts: int = 5, window_seconds: int = 600, lockout_seconds: int = 600):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._lock = threading.Lock()

    def is_locked(self, ip: str) -> Tuple[bool, int]:
        """Returns (is_locked, remaining_seconds). Safe-listed IPs are never locked."""
        clean_ip = ip.strip()
        if not clean_ip or is_safe_ip(clean_ip):
            return False, 0
        with self._lock:
            return db_is_locked(
                clean_ip,
                window_seconds=self.window_seconds,
                max_attempts=self.max_attempts,
                lockout_seconds=self.lockout_seconds
            )

    def record_failure(self, ip: str) -> int:
        """Records a failed login attempt and returns total recent failures."""
        clean_ip = ip.strip()
        if not clean_ip or is_safe_ip(clean_ip):
            return 0
        with self._lock:
            return db_record_failure(
                clean_ip,
                window_seconds=self.window_seconds,
                max_attempts=self.max_attempts,
                lockout_seconds=self.lockout_seconds
            )

    def record_success(self, ip: str):
        """Clears failed attempts for an IP upon successful authentication."""
        clean_ip = ip.strip()
        if not clean_ip:
            return
        with self._lock:
            db_record_success(clean_ip)

# Global singleton
login_limiter = LoginRateLimiter(max_attempts=5, window_seconds=600, lockout_seconds=600)

