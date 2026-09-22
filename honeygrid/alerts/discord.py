import requests
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from honeygrid.config import settings
from honeygrid.models import IncidentEvent, Token, User

def send_discord_alert(event: IncidentEvent, token: Optional[Token] = None) -> bool:
    """
    Sends a rich SOC security alert to the configured Discord webhook.
    Highlights the exact attacker IP, threat score, VPN/Tor flags, geolocation, hardware, and token context.
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
        
    # Threat score badge
    if event.connection_type == "Authorized Operator Test" or event.threat_score == 0:
        score_indicator = "🟢 0% RISK (OPERATOR TEST)"
    elif event.threat_score >= 60:
        score_indicator = "🔴 HIGH RISK"
    elif event.threat_score >= 30:
        score_indicator = "🟠 ELEVATED"
    else:
        score_indicator = "🟡 MODERATE"

    embed_fields = [
        {
            "name": "🎯 Attacker IP Address",
            "value": f"**`{event.attacker_ip}`**" + (" *(Local/Loopback)*" if event.is_local_ip else " *(Public Routable)*"),
            "inline": False
        },
        {
            "name": "🛡️ Adversary Threat Score & Connection",
            "value": f"**`{event.threat_score}%`** ({score_indicator})\n**Type:** `{event.connection_type}`",
            "inline": True
        },
        {
            "name": "🌍 Geolocation & Network",
            "value": f"**Location:** {geo_summary}\n**ISP / ASN:** {event.geo_isp} ({event.geo_asn})",
            "inline": True
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
        }
    ])

    # Hardware & Environment fingerprint if browser telemetry was gathered
    hardware_lines = []
    if event.gpu_renderer and event.gpu_renderer != "Unknown":
        hardware_lines.append(f"• **GPU:** `{event.gpu_renderer}`")
    if event.screen_res:
        hardware_lines.append(f"• **Screen:** `{event.screen_res}`")
    if event.cpu_cores:
        hardware_lines.append(f"• **CPU Cores:** `{event.cpu_cores}`")
    if event.local_lan_ip:
        hardware_lines.append(f"• **WebRTC LAN Leak:** `{event.local_lan_ip}`")

    if hardware_lines:
        embed_fields.append({
            "name": "💻 Client Hardware & Browser Fingerprint",
            "value": "\n".join(hardware_lines),
            "inline": False
        })

    embed_fields.extend([
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

    if event.connection_type == "Authorized Operator Test" or event.threat_score == 0:
        embed_color = 0x10B981
        embed_title = "🟢 AUDIT / TEST: CANARY VERIFIED BY OPERATOR"
        embed_desc = f"Authorized operator test detected from Safe-Listed IP `{event.attacker_ip}`. Active threat response is suppressed."
    else:
        embed_color = 0xE74C3C if event.threat_score >= 50 else 0xE67E22
        embed_title = "🚨 SECURITY INCIDENT: HONEYTOKEN TRIPPED"
        embed_desc = "An adversary has touched a monitored deception asset. Immediate incident triage is recommended."

    payload = {
        "username": "HoneyGrid Sentinel",
        "avatar_url": "https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/shield-halved.svg",
        "embeds": [
            {
                "title": embed_title,
                "description": embed_desc,
                "color": embed_color,
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
        return resp.status_code in (200, 204)
    except Exception as e:
        print(f"[!] Failed to deliver Discord webhook: {e}")
        return False

def send_discord_signup_alert(
    user: User,
    client_ip: str,
    user_agent: str,
    client_tool: str = "Unknown",
    geo_data: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Sends an executive defense-grade notification to the configured Discord Sign-Up Webhook
    whenever a new operator registers on HoneyGrid Sentinel.
    """
    webhook_url = settings.DISCORD_SIGNUP_WEBHOOK_URL or settings.DISCORD_WEBHOOK_URL
    if not webhook_url or "YOUR_WEBHOOK" in webhook_url:
        print("[!] Discord signup alert skipped: No valid webhook configured.")
        return False

    is_admin = user.is_admin or user.role == "admin"
    embed_color = 0xF59E0B if is_admin else 0x10B981
    role_badge = "👑 MASTER ADMINISTRATOR" if is_admin else "🛡️ SECURITY OPERATOR"

    geo = geo_data or {}
    country = geo.get("country", "Unknown")
    city = geo.get("city", "Unknown")
    region = geo.get("region", "Unknown")
    isp = geo.get("isp", "Unknown")
    asn = geo.get("asn", "Unknown")
    location_str = f"{city}, {region}, {country}" if country != "Unknown" else "Unresolved / Local Network"

    embed_fields = [
        {
            "name": "👤 Operator Account",
            "value": f"**Email:** `{user.email}`\n**Role:** `{role_badge}`\n**User ID:** `{user.id}`",
            "inline": False
        },
        {
            "name": "🌐 Network Origin & Provider",
            "value": f"**IP Address:** `{client_ip}`\n**Location:** {location_str}\n**ISP / ASN:** {isp} ({asn})",
            "inline": False
        },
        {
            "name": "💻 Client Environment & Tool",
            "value": f"**Detected Client:** `{client_tool}`\n**User-Agent:** ```{user_agent[:200] if user_agent else 'Unknown'}```",
            "inline": False
        },
        {
            "name": "🔒 Security Attestation",
            "value": "✅ **Anti-Bot Honeypot:** `PASSED`\n✅ **Visual CAPTCHA:** `VERIFIED`\n✅ **Password Encryption:** `PBKDF2-HMAC-SHA256 (310k Rounds)`",
            "inline": True
        },
        {
            "name": "⏱️ Account Provisioned",
            "value": f"<t:{int(datetime.now(timezone.utc).timestamp())}:F>",
            "inline": True
        }
    ]

    payload = {
        "username": "HoneyGrid Sentinel • IAM",
        "avatar_url": "https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/shield-halved.svg",
        "embeds": [
            {
                "title": f"✨ NEW OPERATOR REGISTRATION // {user.email}",
                "description": f"A new operator account has been provisioned on HoneyGrid Sentinel with role **{user.role.upper()}**.",
                "color": embed_color,
                "fields": embed_fields,
                "footer": {
                    "text": "HoneyGrid Sentinel • Identity & Access Management Gate"
                },
                "timestamp": user.created_at or datetime.now(timezone.utc).isoformat()
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
        return resp.status_code in (200, 204)
    except Exception as e:
        print(f"[!] Failed to deliver Discord sign-up webhook: {e}")
        return False
