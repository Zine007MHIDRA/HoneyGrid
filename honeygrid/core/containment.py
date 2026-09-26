import sys
import subprocess
import re
import ipaddress
from typing import Dict, List, Any, Optional

def sanitize_ip(ip: str) -> str:
    return re.sub(r"[^a-zA-Z0-9\.\:]", "_", ip)

def validate_containment_ip(ip: Any) -> Optional[str]:
    """Returns the canonical address when it is a single, publicly routable IP; otherwise None.
    Rejects CIDR ranges, 'any', private/loopback/link-local/reserved/multicast/unspecified addresses,
    and anything that isn't an IP at all (which is also what keeps it out of the netsh command line)."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except (ValueError, TypeError):
        return None
    if (not addr.is_global) or addr.is_multicast or addr.is_unspecified or addr.is_reserved:
        return None
    return str(addr)

def block_ip(ip_address: str, dry_run: bool = False) -> Dict[str, Any]:
    """
    Automated Incident Response Playbook:
    Isolates an attacker IP address by generating and applying a Windows Firewall inbound block rule.
    """
    rule_name = f"HoneyGrid-Block-{sanitize_ip(str(ip_address))}"
    cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'

    result = {
        "ip": ip_address,
        "rule_name": rule_name,
        "command": cmd,
        "platform": sys.platform,
        "applied": False,
        "message": ""
    }

    # Defense-in-depth: Never isolate a safe-listed operator IP under any circumstances
    try:
        from honeygrid.database import is_safe_ip
        if is_safe_ip(ip_address):
            result["message"] = f"Containment refused: IP {ip_address} is protected by Operator Safe List."
            return result
    except Exception:
        pass

    clean_ip = validate_containment_ip(ip_address)
    if not clean_ip:
        result["message"] = "Containment refused: only a single public IP address can be isolated."
        return result
    args = ["netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block", f"remoteip={clean_ip}"]

    if dry_run or sys.platform != "win32":
        result["message"] = f"Dry-run / Non-Windows simulation: Rule '{rule_name}' generated successfully."
        return result

    try:
        proc = subprocess.run(args, shell=False, capture_output=True, text=True, check=False)
        if proc.returncode == 0:
            result["applied"] = True
            result["message"] = f"Successfully applied Windows Firewall block rule for {ip_address}."
        else:
            err = proc.stderr.strip() or proc.stdout.strip()
            if "Run as administrator" in err or "elevation" in err.lower() or proc.returncode != 0:
                result["message"] = (
                    f"Command requires Administrator elevation. Generated command:\n  {cmd}\n"
                    f"To apply manually, run PowerShell as Administrator."
                )
            else:
                result["message"] = f"Firewall command exited with code {proc.returncode}: {err}"
    except Exception as e:
        result["message"] = f"Failed to execute firewall rule: {str(e)}"
        
    return result

def unblock_ip(ip_address: str) -> Dict[str, Any]:
    """Removes a previously created HoneyGrid firewall block rule."""
    rule_name = f"HoneyGrid-Block-{sanitize_ip(str(ip_address))}"
    cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
    args = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
    
    result = {
        "ip": ip_address,
        "rule_name": rule_name,
        "command": cmd,
        "removed": False,
        "message": ""
    }
    
    if sys.platform != "win32":
        result["message"] = f"Simulated unblock of {ip_address} on {sys.platform}."
        result["removed"] = True
        return result

    try:
        proc = subprocess.run(args, shell=False, capture_output=True, text=True, check=False)
        if proc.returncode == 0:
            result["removed"] = True
            result["message"] = f"Successfully removed firewall block rule for {ip_address}."
        else:
            result["message"] = proc.stderr.strip() or proc.stdout.strip()
    except Exception as e:
        result["message"] = str(e)
        
    return result
