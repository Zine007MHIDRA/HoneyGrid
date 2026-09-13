import ipaddress
import re
from typing import Dict, Tuple, Optional
from fastapi import Request

# Common attack / recon tools and browsers signatures
TOOL_SIGNATURES = [
    (r"curl\/", "cURL CLI"),
    (r"Wget\/", "Wget Utility"),
    (r"python-requests", "Python Requests (Automated Script)"),
    (r"aiohttp", "Python aiohttp (Asynchronous Bot)"),
    (r"PostmanRuntime", "Postman API Client"),
    (r"insomnia", "Insomnia API Client"),
    (r"sqlmap", "SQLMap Automated Exploit Tool"),
    (r"Nikto", "Nikto Web Vulnerability Scanner"),
    (r"nmap", "Nmap Scripting Engine"),
    (r"masscan", "Masscan Port Scanner"),
    (r"Go-http-client", "Golang HTTP Client"),
    (r"HTTPie", "HTTPie CLI"),
    (r"BurpCollaborator|BurpSuite", "Burp Suite Professional"),
    (r"ZAP", "OWASP ZAP Scanner"),
    (r"Edg\/", "Microsoft Edge Browser"),
    (r"Chrome\/", "Google Chrome Browser"),
    (r"Firefox\/", "Mozilla Firefox"),
    (r"Safari\/", "Apple Safari"),
]

def extract_client_ip(request: Request) -> Tuple[str, bool]:
    """
    Extract the real attacker IP address from direct TCP connection or reverse proxy headers.
    Returns: (ip_address, is_local_private)
    """
    headers = request.headers
    
    # Priority order for proxy/edge IP headers
    proxy_headers = [
        "cf-connecting-ip",     # Cloudflare
        "true-client-ip",       # Akamai / Cloudflare
        "x-real-ip",            # Nginx reverse proxy
        "x-forwarded-for",      # Standard proxy chain (first IP is the original client)
        "x-client-ip"
    ]
    
    ip_str = None
    for header in proxy_headers:
        val = headers.get(header)
        if val:
            # X-Forwarded-For may contain multiple IPs: "client, proxy1, proxy2"
            parts = [p.strip() for p in val.split(",")]
            if parts and parts[0]:
                ip_str = parts[0]
                break

    # Fallback to direct client socket
    if not ip_str:
        if request.client and request.client.host:
            ip_str = request.client.host
        else:
            ip_str = "127.0.0.1"
            
    # Check if IP is private/local
    is_local = is_private_ip(ip_str)
    return ip_str, is_local

def is_private_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
    except ValueError:
        return True

def identify_client_tool(user_agent: Optional[str]) -> str:
    """Classifies client tool / browser from User-Agent string."""
    if not user_agent or user_agent.strip() == "":
        return "Unknown / Headless (No User-Agent)"
        
    for pattern, name in TOOL_SIGNATURES:
        if re.search(pattern, user_agent, re.IGNORECASE):
            return name
            
    return "Custom Client / Browser"
