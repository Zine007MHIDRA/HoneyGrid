import requests
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from honeygrid.config import settings
from honeygrid.models import IncidentEvent, Token

def send_discord_alert(event: IncidentEvent, token: Optional[Token] = None) -> bool:
    """
    Sends a rich SOC security alert to the configured Discord webhook.
    Highlights the exact attacker IP, geolocation, client fingerprint, and token context.
    """
    webhook_url = settings.DISCORD_WEBHOOK_URL
    if not webhook_url or "YOUR_WEBHOOK" in webhook_url:
        print("[!] Discord alert skipped: No valid DISCORD_WEBHOOK_URL configured.")
        return False

    token_label = token.label if token else "Unknown / Ad-hoc Trap"
    token_type = token.token_type if token else "Canary"
    
    # Map link if coordinates exist
    maps_link = ""
    if event.geo_lat is not None and event.geo_lon is not None:
        maps_link = f"https://www.google.com/maps/search/?api=1&query={event.geo_lat},{event.geo_lon}"

    geo_summary = f"{event.geo_city}, {event.geo_region}, {event.geo_country}"
    if event.is_local_ip:
        geo_summary = "Local / Internal Network (Loopback or RFC1918)"
        
    embed_fields = [
        {
            "name": "🎯 Attacker IP Address",
            "value": f"**`{event.attacker_ip}`**" + (" *(Local/Loopback)*" if event.is_local_ip else " *(Public Routable)*"),
            "inline": False
        },
        {
            "name": "🌍 Geolocation & Network",
            "value": f"**Location:** {geo_summary}\n**ISP / ASN:** {event.geo_isp} ({event.geo_asn})",
            "inline": False
        }
    ]

    if maps_link:
        embed_fields.append({
            "name": "📍 Location Coordinates",
            "value": f"[{event.geo_lat}, {event.geo_lon} (View on Google Maps)]({maps_link})",
            "inline": True
        })

    embed_fields.extend([
        {
            "name": "🏷️ Tripped Token",
            "value": f"**Name:** {token_label}\n**Type:** `{token_type}`\n**ID:** `{event.token_id}`",
            "inline": True
        },
        {
            "name": "🛠️ Attacker Client Fingerprint",
            "value": f"**Detected Tool:** `{event.client_tool}`\n**Method:** `{event.http_method or 'GET'}`\n**Endpoint:** `{event.request_path or '/t/' + event.token_id}`",
            "inline": False
        },
        {
            "name": "🛡️ MITRE ATT&CK",
            "value": f"`{event.mitre_technique}`",
            "inline": True
        },
        {
            "name": "User-Agent Header",
            "value": f"```{event.user_agent[:250] if event.user_agent else 'None'}```",
            "inline": False
        }
    ])

    payload = {
        "username": "HoneyGrid Sentinel",
        "avatar_url": "https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/shield-halved.svg",
        "embeds": [
            {
                "title": "🚨 SECURITY INCIDENT: HONEYTOKEN TRIPPED",
                "description": f"An adversary has touched a monitored deception asset. Immediate incident triage is recommended.",
                "color": 0xE74C3C,  # High-vis Crimson Red
                "fields": embed_fields,
                "footer": {
                    "text": "HoneyGrid Deception Platform • Threat Detection & Triage"
                },
                "timestamp": event.timestamp or datetime.now(timezone.utc).isoformat()
            }
        ]
    }

    try:
        resp = requests.post(
            webhook_url,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=5.0
        )
        if resp.status_code in (200, 204):
            return True
        else:
            print(f"[!] Discord webhook returned HTTP {resp.status_code}: {resp.text}")
            return False
    except Exception as e:
        print(f"[!] Failed to deliver Discord webhook: {e}")
        return False
