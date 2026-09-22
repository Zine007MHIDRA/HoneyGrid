import os
import time
import requests
import threading
from pathlib import Path
from typing import Set, Optional
from honeygrid.config import BASE_DIR

FALLBACK_TOR_SEEDS: Set[str] = {
    "185.220.101.5",
    "185.220.101.6",
    "185.220.101.7",
    "185.220.101.8",
    "185.220.101.9",
    "185.220.101.10",
    "185.220.101.11",
    "185.220.101.12",
    "185.220.102.240",
    "185.220.102.241",
    "185.220.102.242",
    "185.220.103.4",
    "185.220.103.5",
    "171.25.193.20",
    "171.25.193.25",
    "51.15.43.205",
    "192.42.116.16",
    "199.249.230.70"
}

class TorDetector:
    """
    High-performance Tor Exit-Node detection engine.
    Fetches the official Tor Project bulk exit list over HTTPS with sensible timeouts,
    caches the dataset in memory and on disk, and provides instant O(1) IP classification.
    """
    TOR_BULK_EXIT_URL = "https://check.torproject.org/torbulkexitlist"
    CACHE_TTL_SECONDS = 7200  # 2 hours

    def __init__(self, cache_file: Optional[Path] = None):
        self._lock = threading.Lock()
        self._exit_nodes: Set[str] = set()
        self._test_nodes: Set[str] = set()
        self._last_refresh: float = 0.0
        self._cache_file = cache_file or (BASE_DIR / ".tor_exit_cache.txt")
        self._load_disk_cache_or_seeds()

    def _load_disk_cache_or_seeds(self):
        """Loads cached exit nodes from disk if available, otherwise initializes fallback seeds."""
        if self._cache_file.exists():
            try:
                with open(self._cache_file, "r", encoding="utf-8") as f:
                    ips = {line.strip() for line in f if line.strip() and not line.startswith("#")}
                if len(ips) >= 10:
                    self._exit_nodes = ips
                    self._last_refresh = self._cache_file.stat().st_mtime
                    return
            except Exception:
                pass
        
        self._exit_nodes = set(FALLBACK_TOR_SEEDS)

    def refresh(self, force: bool = False) -> int:
        """
        Refreshes exit node list from official Tor Project HTTPS endpoint.
        Returns count of loaded exit nodes.
        """
        now = time.time()
        with self._lock:
            if not force and (now - self._last_refresh < self.CACHE_TTL_SECONDS) and len(self._exit_nodes) > 20:
                return len(self._exit_nodes)

            try:
                resp = requests.get(self.TOR_BULK_EXIT_URL, timeout=3.5)
                if resp.status_code == 200 and resp.text:
                    lines = resp.text.splitlines()
                    fetched_ips = {line.strip() for line in lines if line.strip() and not line.startswith("#")}
                    if len(fetched_ips) >= 50:
                        self._exit_nodes = fetched_ips
                        self._last_refresh = now
                        try:
                            with open(self._cache_file, "w", encoding="utf-8") as f:
                                f.write("\n".join(sorted(fetched_ips)))
                        except Exception:
                            pass
                        return len(self._exit_nodes)
            except Exception:
                pass

            self._last_refresh = now
            return len(self._exit_nodes)

    def is_tor_exit_node(self, ip_address: str) -> bool:
        """Instant O(1) Tor exit node classification."""
        clean_ip = ip_address.strip()
        if not clean_ip:
            return False

        if clean_ip in self._test_nodes:
            return True

        if time.time() - self._last_refresh > self.CACHE_TTL_SECONDS:
            self.refresh(force=False)

        return clean_ip in self._exit_nodes

    def add_test_exit_node(self, ip_address: str):
        """Test fixture: register an IP as a known Tor exit node."""
        self._test_nodes.add(ip_address.strip())

    def remove_test_exit_node(self, ip_address: str):
        """Test fixture: unregister an IP from test overrides."""
        self._test_nodes.discard(ip_address.strip())

    def clear_test_nodes(self):
        """Test fixture: clear test overrides."""
        self._test_nodes.clear()

tor_detector = TorDetector()

def is_tor_exit_node(ip_address: str) -> bool:
    return tor_detector.is_tor_exit_node(ip_address)
