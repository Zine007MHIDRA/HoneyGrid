import time
import threading
from typing import Dict, List, Tuple

class LoginRateLimiter:
    """
    Thread-safe sliding window rate limiter to mitigate credential stuffing
    and brute-force password guessing attacks against operator accounts.
    """
    def __init__(self, max_attempts: int = 5, window_seconds: int = 600, lockout_seconds: int = 600):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._lock = threading.Lock()
        self._failed_attempts: Dict[str, List[float]] = {}
        self._lockouts: Dict[str, float] = {}

    def is_locked(self, ip: str) -> Tuple[bool, int]:
        """Returns (is_locked, remaining_seconds)."""
        now = time.time()
        with self._lock:
            # Check active lockout
            locked_until = self._lockouts.get(ip, 0)
            if now < locked_until:
                return True, max(1, int(locked_until - now))
            elif locked_until != 0:
                del self._lockouts[ip]

            # Prune old attempts outside sliding window
            attempts = self._failed_attempts.get(ip, [])
            valid_attempts = [t for t in attempts if now - t < self.window_seconds]
            self._failed_attempts[ip] = valid_attempts

            if len(valid_attempts) >= self.max_attempts:
                # Trigger new lockout
                self._lockouts[ip] = now + self.lockout_seconds
                self._failed_attempts[ip] = []
                return True, self.lockout_seconds

            return False, 0

    def record_failure(self, ip: str) -> int:
        """Records a failed login attempt and returns total recent failures."""
        now = time.time()
        with self._lock:
            attempts = self._failed_attempts.get(ip, [])
            valid_attempts = [t for t in attempts if now - t < self.window_seconds]
            valid_attempts.append(now)
            self._failed_attempts[ip] = valid_attempts

            if len(valid_attempts) >= self.max_attempts:
                self._lockouts[ip] = now + self.lockout_seconds
                self._failed_attempts[ip] = []
                return self.max_attempts

            return len(valid_attempts)

    def record_success(self, ip: str):
        """Clears failed attempts for an IP upon successful authentication."""
        with self._lock:
            self._failed_attempts.pop(ip, None)
            self._lockouts.pop(ip, None)

# Global singleton
login_limiter = LoginRateLimiter(max_attempts=5, window_seconds=600, lockout_seconds=600)
