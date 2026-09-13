import time
import socket
import threading
from pathlib import Path
from typing import Dict, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent
from honeygrid.models import IncidentEvent, Token
from honeygrid.database import get_token, record_incident
from honeygrid.alerts.discord import send_discord_alert

class HoneyfileHandler(FileSystemEventHandler):
    def __init__(self, monitored_files: Dict[str, Token]):
        super().__init__()
        self.monitored_files = monitored_files  # normalized_path -> Token
        self.cooldowns: Dict[str, float] = {}

    def on_modified(self, event: FileSystemEvent):
        self._check_and_trigger(event.src_path, "MODIFIED")

    def on_opened(self, event: FileSystemEvent):
        self._check_and_trigger(event.src_path, "OPENED/ACCESSED")

    def _check_and_trigger(self, file_path: str, action: str):
        normalized = str(Path(file_path).resolve())
        now = time.time()
        
        # Debounce multiple events within 3 seconds
        if normalized in self.cooldowns and (now - self.cooldowns[normalized] < 3.0):
            return
            
        token = self.monitored_files.get(normalized)
        if token:
            self.cooldowns[normalized] = now
            hostname = socket.gethostname()
            
            incident = IncidentEvent(
                token_id=token.id,
                attacker_ip=f"LocalHost ({hostname})",
                is_local_ip=True,
                client_tool="Filesystem Access (Process / User Read)",
                user_agent=f"File {action}: {Path(normalized).name}",
                http_method="FS_TRIPWIRE",
                request_path=normalized,
                geo_country="Local Machine",
                geo_city="Host Filesystem",
                geo_region="Local",
                geo_isp="Internal Windows IO",
                geo_asn="N/A",
                mitre_technique="T1083: File and Directory Discovery"
            )
            
            record_incident(incident)
            send_discord_alert(incident, token)
            print(f"[!] HONEYFILE TRIPPED: {normalized} was {action}!")

def start_honeyfile_monitor(tokens_with_paths: Dict[str, Token]):
    """Starts watching parent folders of monitored honeyfiles in a background thread."""
    if not tokens_with_paths:
        print("[*] No honeyfiles registered to monitor.")
        return None

    event_handler = HoneyfileHandler(tokens_with_paths)
    observer = Observer()
    
    watched_dirs: Set[str] = set()
    for file_path in tokens_with_paths.keys():
        parent_dir = str(Path(file_path).parent.resolve())
        if parent_dir not in watched_dirs:
            observer.schedule(event_handler, path=parent_dir, recursive=False)
            watched_dirs.add(parent_dir)
            
    observer.start()
    return observer
