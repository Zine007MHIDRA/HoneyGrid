import json
import logging
from typing import Optional, Dict, Any
from honeygrid.database import record_audit_log

audit_logger = logging.getLogger("honeygrid.audit")
if not audit_logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[AUDIT %(asctime)s] %(message)s")
    handler.setFormatter(formatter)
    audit_logger.addHandler(handler)
    audit_logger.setLevel(logging.INFO)

SENSITIVE_KEYS = {"password", "secret", "token", "session", "cookie", "salt", "key", "authorization", "auth"}

def redact_sensitive(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not data:
        return {}
    clean = {}
    for k, v in data.items():
        if any(s in k.lower() for s in SENSITIVE_KEYS):
            clean[k] = "[REDACTED]"
        elif isinstance(v, dict):
            clean[k] = redact_sensitive(v)
        else:
            clean[k] = v
    return clean

def log_audit_event(
    action: str,
    outcome: str,
    actor: str = "system",
    client_ip: str = "127.0.0.1",
    target: str = "",
    metadata: Optional[Dict[str, Any]] = None
) -> int:
    """
    Records a structured security audit event to the database and standard logging.
    Guarantees no sensitive credentials or tokens are exposed.
    """
    clean_meta = redact_sensitive(metadata)
    try:
        log_id = record_audit_log(
            action=action,
            outcome=outcome,
            actor=actor,
            client_ip=client_ip,
            target=target,
            metadata=clean_meta
        )
        audit_logger.info(json.dumps({
            "action": action,
            "outcome": outcome,
            "actor": actor,
            "client_ip": client_ip,
            "target": target,
            "metadata": clean_meta
        }))
        return log_id
    except Exception as e:
        audit_logger.error(f"Failed to record audit log: {e}")
        return -1
