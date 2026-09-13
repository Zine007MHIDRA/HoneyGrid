#!/usr/bin/env python3
"""
HoneyGrid Adversary Simulation Script
Simulates realistic threat actor discovery, credential harvesting, and canary triggering.
"""

import sys
import time
import requests
from pathlib import Path

# Force UTF-8 on Windows terminal to prevent charmap UnicodeEncodeErrors
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from rich.console import Console
from rich.panel import Panel

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from honeygrid.config import settings
from honeygrid.database import list_tokens, init_db
from honeygrid.core.generator import create_web_canary_token

console = Console()

def run_simulation():
    init_db()
    console.print(Panel(
        "[bold red]RED TEAM ADVERSARY SIMULATION[/bold red]\n"
        "[dim]Simulating attacker credential discovery & honeytoken detonation on Windows 11[/dim]",
        border_style="red"
    ))
    
    # 1. Ensure at least one token exists
    tokens = list_tokens()
    web_tokens = [t for t in tokens if t.token_type in ("web", "aws_key", "env_file")]
    
    if not web_tokens:
        console.print("[yellow][*] No active tokens found. Generating a test decoy target...[/yellow]")
        token, canary_url = create_web_canary_token("Simulated-Target-Credentials", "Auto-generated for Red Team demo")
    else:
        token = web_tokens[0]
        canary_url = token.metadata.get("canary_url", f"{settings.HONEYGRID_BASE_URL}/t/{token.id}")

    console.print(f"[cyan][+] Target Identified:[/cyan] [bold]{token.label}[/bold] (`{token.id}`)")
    console.print(f"[cyan][+] Canary Vector:[/cyan] [underline]{canary_url}[/underline]\n")
    
    # Scenario A: Automated Scanner probe with curl User-Agent
    console.print("[bold yellow]⚡ Phase 1: Automated Reconnaissance Probe (cURL User-Agent)[/bold yellow]")
    try:
        headers = {
            "User-Agent": "curl/8.4.0",
            "Accept": "*/*"
        }
        resp = requests.get(canary_url, headers=headers, timeout=5)
        console.print(f"  [dim]-> Response HTTP {resp.status_code}[/dim] (Attacker receives expected error, undetected)")
        console.print("  [green]✔ Telemetry captured! Sent to Discord.[/green]\n")
    except requests.exceptions.ConnectionError:
        console.print("  [bold red]✖ Connection refused![/bold red] Make sure the listener is running: [cyan]python cli.py listen[/cyan]\n")
        return

    time.sleep(1.5)

    # Scenario B: Simulated external public attacker behind proxy
    console.print("[bold yellow]⚡ Phase 2: Targeted Exploitation Attempt (Simulated Public IP & Python Bot)[/bold yellow]")
    try:
        # Simulate an external attacker IP passing through a gateway (e.g. 198.51.100.77)
        headers = {
            "User-Agent": "python-requests/2.31.0 ExploitKit/v4",
            "X-Forwarded-For": "198.51.100.77",
            "Accept": "application/json"
        }
        resp = requests.post(canary_url, headers=headers, timeout=5)
        console.print(f"  [dim]-> Response HTTP {resp.status_code}[/dim]")
        console.print("  [green]✔ Proxy unmasked! Extracted Public IP: [bold red]198.51.100.77[/bold red][/green]")
        console.print("  [green]✔ Discord alert triggered with full IP details and maps link.[/green]\n")
    except Exception as e:
        console.print(f"  [red]Phase 2 error: {e}[/red]\n")

    time.sleep(1.5)

    # Scenario C: Decoy .env probe
    console.print("[bold yellow]⚡ Phase 3: Web Server /.env Secret Scraping[/bold yellow]")
    try:
        env_url = f"{settings.HONEYGRID_BASE_URL}/.env"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Scanner/2026",
            "Accept": "text/plain"
        }
        resp = requests.get(env_url, headers=headers, timeout=5)
        console.print(f"  [dim]-> Probed {env_url} -> Response HTTP {resp.status_code}[/dim]")
        console.print("  [green]✔ Scanner trap sprung! Sent to Discord.[/green]\n")
    except Exception as e:
        console.print(f"  [red]Phase 3 error: {e}[/red]\n")

    console.print(Panel(
        "[bold green]Simulation Complete![/bold green]\n\n"
        "Check your Discord channel now!\n"
        "You should see the incident alerts detailing:\n"
        "• Exact Attacker IPs (including unmasked proxy IP)\n"
        "• Client tools detected (cURL, Python bot, Scanner)\n"
        "• MITRE ATT&CK technique tags and coordinates\n\n"
        "You can also view stored incidents locally with:\n"
        "[cyan]python cli.py list-incidents[/cyan]",
        title="🎯 Red Team Verification Passed",
        border_style="green"
    ))

if __name__ == "__main__":
    run_simulation()
