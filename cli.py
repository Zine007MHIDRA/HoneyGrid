#!/usr/bin/env python3
import sys
import os
import argparse
from pathlib import Path

# Force UTF-8 on Windows terminal to prevent charmap UnicodeEncodeErrors
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from honeygrid.config import settings
from honeygrid.database import init_db, list_tokens, list_incidents, get_token, save_token
from honeygrid.models import IncidentEvent, Token
from honeygrid.core.generator import (
    create_web_canary_token,
    create_aws_honeytoken,
    create_env_honeytoken,
    create_honeyfile_tripwire
)
from honeygrid.core.pdf_canary import create_canary_pdf
from honeygrid.alerts.discord import send_discord_alert
from honeygrid.core.geo import lookup_ip_geolocation

console = Console()

def banner():
    console.print(Panel.fit(
        "[bold red]HONEYGRID[/bold red] - [yellow]Deception Technology & Honeytoken Platform[/yellow]\n"
        "[dim]Active Defense, Decoy Generation & Threat Telemetry for Incident Responders[/dim]",
        border_style="red"
    ))

def cmd_init():
    init_db()
    console.print("[green]✔ Database initialized successfully at:[/green]", settings.HONEYGRID_DB_PATH)

def cmd_generate(args):
    init_db()
    token_type = args.type.lower()
    label = args.label or f"Decoy-{token_type.upper()}"
    desc = args.desc or f"Generated {token_type} honeytoken asset"
    
    if token_type == "web":
        token, url = create_web_canary_token(label, desc)
        console.print(Panel(
            f"[bold green]Canary URL Created Successfully![/bold green]\n\n"
            f"[bold cyan]Token ID:[/bold cyan] {token.id}\n"
            f"[bold cyan]Label:[/bold cyan]    {token.label}\n"
            f"[bold yellow]Canary URL:[/bold yellow] [underline]{url}[/underline]\n\n"
            f"[dim]Embed this URL in scripts, docs, or web bookmarks to detect unauthorized access.[/dim]",
            title="🎯 Web Canary Token",
            border_style="green"
        ))
        
    elif token_type == "aws":
        token, data = create_aws_honeytoken(label, desc)
        out_dir = Path("traps")
        out_dir.mkdir(exist_ok=True)
        out_file = out_dir / "aws_credentials_decoy"
        with open(out_file, "w") as f:
            f.write(data["file_content"])
            
        console.print(Panel(
            f"[bold green]AWS Decoy Credentials Generated![/bold green]\n\n"
            f"[bold cyan]Access Key ID:[/bold cyan] {data['access_key_id']}\n"
            f"[bold cyan]Secret Key:[/bold cyan]    {data['secret_key'][:6]}...[dim](truncated)[/dim]\n"
            f"[bold cyan]Saved To:[/bold cyan]      {out_file.resolve()}\n"
            f"[bold yellow]Trigger URL:[/bold yellow]   {data['canary_url']}\n\n"
            f"[dim]Place this in ~/.aws/credentials or inside repos to catch credential hunters.[/dim]",
            title="☁️ AWS IAM Honeytoken",
            border_style="yellow"
        ))
        
    elif token_type == "env":
        token, content = create_env_honeytoken(label, desc)
        out_dir = Path("traps")
        out_dir.mkdir(exist_ok=True)
        out_file = out_dir / ".env.production.backup"
        with open(out_file, "w") as f:
            f.write(content)
            
        console.print(Panel(
            f"[bold green]Decoy .env File Created![/bold green]\n\n"
            f"[bold cyan]Saved To:[/bold cyan]    {out_file.resolve()}\n"
            f"[bold cyan]Token ID:[/bold cyan]    {token.id}\n"
            f"[bold yellow]Sync URL:[/bold yellow]    {token.metadata.get('canary_url')}\n\n"
            f"[dim]Contains plausible database URLs and API keys wired to the canary listener.[/dim]",
            title="📄 Decoy .env Honeytoken",
            border_style="green"
        ))

    elif token_type == "pdf":
        out_dir = Path("traps")
        out_dir.mkdir(exist_ok=True)
        out_file = out_dir / (args.filename or "Executive_Salaries_Q4_2026.pdf")
        token, path = create_canary_pdf(str(out_file), label=label)
        console.print(Panel(
            f"[bold green]Canary PDF Generated![/bold green]\n\n"
            f"[bold cyan]Document Path:[/bold cyan] {path}\n"
            f"[bold cyan]Token ID:[/bold cyan]      {token.id}\n"
            f"[bold yellow]Beacon URL:[/bold yellow]    {token.metadata.get('canary_url')}\n\n"
            f"[dim]Plant this in a shared network drive or Downloads folder to trap insider threats.[/dim]",
            title="📑 Canary PDF Tripwire",
            border_style="red"
        ))

    elif token_type == "file":
        if not args.path:
            console.print("[red]Error: --path is required for file tripwires (e.g. --path ./traps/secrets.txt)[/red]")
            return
        token = create_honeyfile_tripwire(args.path, label, desc)
        console.print(Panel(
            f"[bold green]Honeyfile Tripwire Registered![/bold green]\n\n"
            f"[bold cyan]Watched Path:[/bold cyan] {token.metadata.get('target_path')}\n"
            f"[bold cyan]Token ID:[/bold cyan]     {token.id}\n\n"
            f"[dim]Run 'python cli.py listen' to actively monitor this file for access/modification.[/dim]",
            title="📁 Local Honeyfile Tripwire",
            border_style="blue"
        ))
    else:
        console.print(f"[red]Unknown token type: {token_type}. Available: web, aws, env, pdf, file[/red]")

def cmd_list_tokens():
    init_db()
    tokens = list_tokens()
    if not tokens:
        console.print("[yellow]No tokens registered yet. Run 'python cli.py generate --type web' to create one.[/yellow]")
        return
        
    table = Table(title="🛡️ Deployed HoneyGrid Tokens", border_style="cyan")
    table.add_column("Token ID", style="bold cyan")
    table.add_column("Type", style="yellow")
    table.add_column("Label", style="white")
    table.add_column("Triggers", style="bold red", justify="center")
    table.add_column("Created (UTC)", style="dim")
    table.add_column("Status", style="green")

    for t in tokens:
        status = "[green]ACTIVE[/green]" if t.is_active else "[dim]INACTIVE[/dim]"
        table.add_row(t.id, t.token_type, t.label, str(t.trigger_count), t.created_at[:19], status)

    console.print(table)

def cmd_list_incidents():
    init_db()
    incidents = list_incidents(limit=30)
    if not incidents:
        console.print("[yellow]No security incidents recorded yet. All honeytokens are quiet.[/yellow]")
        return
        
    table = Table(title="🚨 Captured Incident Telemetry", border_style="red")
    table.add_column("ID", style="dim", justify="right")
    table.add_column("Timestamp (UTC)", style="dim")
    table.add_column("Token ID", style="cyan")
    table.add_column("Attacker IP", style="bold red")
    table.add_column("Location", style="yellow")
    table.add_column("Client / Tool", style="magenta")
    table.add_column("MITRE TTP", style="white")

    for inc in incidents:
        loc = f"{inc.geo_city}, {inc.geo_country}" if inc.geo_country != "Unknown" else "Internal/Local"
        table.add_row(
            str(inc.id),
            inc.timestamp[:19],
            inc.token_id,
            inc.attacker_ip,
            loc,
            inc.client_tool or "Unknown",
            inc.mitre_technique or "T1552"
        )

    console.print(table)

def cmd_test_alert():
    """Test sending an alert directly to Discord to verify webhook integration."""
    init_db()
    console.print("[cyan]Testing Discord Webhook connection...[/cyan]")
    
    geo = lookup_ip_geolocation("127.0.0.1", fallback_to_public=True)
    test_ip = geo.get("query_ip", "203.0.113.195")
    
    event = IncidentEvent(
        token_id="canary_test_verification",
        attacker_ip=test_ip,
        is_local_ip=False,
        client_tool="HoneyGrid Verification Engine",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Test/1.0",
        http_method="GET",
        request_path="/t/canary_test_verification",
        geo_country=geo.get("country", "Cyber Lab"),
        geo_city=geo.get("city", "Security Ops Center"),
        geo_region=geo.get("region", "Cloud"),
        geo_isp=geo.get("isp", "Defense Network"),
        geo_asn=geo.get("asn", "AS13335"),
        geo_lat=geo.get("lat", 37.7749),
        geo_lon=geo.get("lon", -122.4194),
        mitre_technique="T1552: Unsecured Credentials - Test Verification"
    )
    
    dummy_token = Token(
        id="canary_test_verification",
        token_type="web",
        label="Test Sentinel Verification Token",
        created_at=event.timestamp,
        trigger_count=1
    )
    
    success = send_discord_alert(event, dummy_token)
    if success:
        console.print(Panel(
            f"[bold green]✔ Discord alert dispatched successfully![/bold green]\n\n"
            f"Check your Discord channel. You should see a rich red incident embed with:\n"
            f"• [bold]Attacker IP:[/bold] `{test_ip}`\n"
            f"• [bold]Location:[/bold] {event.geo_city}, {event.geo_country}\n"
            f"• [bold]Google Maps Link & MITRE TTPs[/bold]",
            title="Discord Verification Passed",
            border_style="green"
        ))
    else:
        console.print("[bold red]✖ Failed to send Discord alert.[/bold red] Check DISCORD_WEBHOOK_URL in .env.")

def cmd_listen():
    init_db()
    import uvicorn
    from honeygrid.watchers.file_watcher import start_honeyfile_monitor
    
    # Check for honeyfiles to watch
    all_tokens = list_tokens()
    honeyfiles = {
        t.metadata["target_path"]: t
        for t in all_tokens
        if t.token_type == "honeyfile" and "target_path" in t.metadata
    }
    
    if honeyfiles:
        console.print(f"[green][*] Starting local file watcher for {len(honeyfiles)} honeyfiles...[/green]")
        start_honeyfile_monitor(honeyfiles)

    console.print(Panel(
        f"[bold green]Starting HoneyGrid Canary Sentinel Listener...[/bold green]\n\n"
        f"• [bold cyan]Host:[/bold cyan] {settings.HONEYGRID_HOST}\n"
        f"• [bold cyan]Port:[/bold cyan] {settings.HONEYGRID_PORT}\n"
        f"• [bold cyan]Base URL:[/bold cyan] {settings.HONEYGRID_BASE_URL}\n"
        f"• [bold yellow]Active Endpoints:[/bold yellow] /t/{{token_id}}, /api/v1/auth, /.env\n\n"
        f"[dim]Press Ctrl+C to terminate listener.[/dim]",
        title="🛡️ Sentinel Online",
        border_style="cyan"
    ))
    
    uvicorn.run(
        "honeygrid.server.listener:app",
        host=settings.HONEYGRID_HOST,
        port=settings.HONEYGRID_PORT,
        log_level="info"
    )

def main():
    banner()
    parser = argparse.ArgumentParser(description="HoneyGrid Deception & Honeytoken Platform")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # init
    subparsers.add_parser("init", help="Initialize the HoneyGrid database")

    # generate
    gen_parser = subparsers.add_parser("generate", help="Generate a new honeytoken asset")
    gen_parser.add_argument("--type", choices=["web", "aws", "env", "pdf", "file"], default="web", help="Token type to generate")
    gen_parser.add_argument("--label", type=str, help="Human-readable label for this token")
    gen_parser.add_argument("--desc", type=str, help="Context/notes for where token is deployed")
    gen_parser.add_argument("--path", type=str, help="File path (required for --type file)")
    gen_parser.add_argument("--filename", type=str, help="Custom filename (for --type pdf)")

    # list-tokens
    subparsers.add_parser("list-tokens", help="List all generated honeytokens")

    # list-incidents
    subparsers.add_parser("list-incidents", help="View incident forensics log")

    # test-alert
    subparsers.add_parser("test-alert", help="Send a test verification alert to Discord")

    # listen
    subparsers.add_parser("listen", help="Start the canary listener server & file watcher")

    args = parser.parse_args()

    if args.command == "init":
        cmd_init()
    elif args.command == "generate":
        cmd_generate(args)
    elif args.command == "list-tokens":
        cmd_list_tokens()
    elif args.command == "list-incidents":
        cmd_list_incidents()
    elif args.command == "test-alert":
        cmd_test_alert()
    elif args.command == "listen":
        cmd_listen()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
