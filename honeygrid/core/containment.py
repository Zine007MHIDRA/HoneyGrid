import sys
import subprocess
import re
from typing import Dict, List, Any

def sanitize_ip(ip: str) -> str:
    return re.sub(r"[^a-zA-Z0-9\.\:]", "_", ip)

def block_ip(ip_address: str, dry_run: bool = False) -> Dict[str, Any]:
    """
    Automated Incident Response Playbook:
    Isolates an attacker IP address by generating and applying a Windows Firewall inbound block rule.
    """
    rule_name = f"HoneyGrid-Block-{sanitize_ip(ip_address)}"
    cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
    
    result = {
        "ip": ip_address,
        "rule_name": rule_name,
        "command": cmd,
        "platform": sys.platform,
        "applied": False,
        "message": ""
    }
    
    if dry_run or sys.platform != "win32":
        result["message"] = f"Dry-run / Non-Windows simulation: Rule '{rule_name}' generated successfully."
        return result

    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            check=False
        )
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
    rule_name = f"HoneyGrid-Block-{sanitize_ip(ip_address)}"
    cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
    
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
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
        if proc.returncode == 0:
            result["removed"] = True
            result["message"] = f"Successfully removed firewall block rule for {ip_address}."
        else:
            result["message"] = proc.stderr.strip() or proc.stdout.strip()
    except Exception as e:
        result["message"] = str(e)
        
    return result
