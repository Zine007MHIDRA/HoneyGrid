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

# Network CIDR and IP validation helpers
_PARSED_NETWORKS_CACHE: Dict[str, Any] = {}

def ip_in_networks(ip_str: str, networks: list) -> bool:
    """
    Evaluates whether an IP address belongs to any configured IP or CIDR network.
    Uses cached ip_network objects to avoid re-parsing overhead.
    """
    if not ip_str or not networks:
        return False
    try:
        target_ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    for item in networks:
        item = item.strip()
        if not item:
            continue
        try:
            if "/" in item:
                if item not in _PARSED_NETWORKS_CACHE:
                    _PARSED_NETWORKS_CACHE[item] = ipaddress.ip_network(item, strict=False)
                if target_ip in _PARSED_NETWORKS_CACHE[item]:
                    return True
            else:
                if item not in _PARSED_NETWORKS_CACHE:
                    _PARSED_NETWORKS_CACHE[item] = ipaddress.ip_address(item)
                if target_ip == _PARSED_NETWORKS_CACHE[item]:
                    return True
        except ValueError:
            continue

    return False

def is_valid_ip(ip_str: str) -> bool:
    if not ip_str:
        return False
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def extract_client_ip(
    request: Request,
    trusted_proxies: Optional[list] = None,
    cloudflare_proxies: Optional[list] = None
) -> Tuple[str, bool]:
    """
    Extracts client IP using Provider-Aware Proxy Trust rules:
    1. The direct TCP socket peer (request.client.host) is the ground truth.
    2. If the peer does NOT belong to a configured trusted network, all forwarding
       headers are discarded to prevent client-side spoofing.
    3. Provider-specific headers (e.g., CF-Connecting-IP, True-Client-IP) are ONLY
       honored when the direct peer belongs to Cloudflare's explicit CIDR ranges.
       They are strictly ignored from generic reverse proxies.
    4. For generic trusted proxies, X-Forwarded-For is traversed from right-to-left
       (backwards) skipping trusted proxies to find the true untrusted client.
    5. Preserves localhost development and private network detection.
    """
    headers = request.headers
    
    # 1. Resolve direct socket peer
    direct_peer = "127.0.0.1"
    if request.client and request.client.host:
        direct_peer = request.client.host
        if not is_valid_ip(direct_peer):
            direct_peer = "127.0.0.1"

    # 2. Resolve configured trusted networks
    from honeygrid.config import settings
    if trusted_proxies is None:
        trusted_proxies = settings.get_trusted_proxies()
    if cloudflare_proxies is None:
        cloudflare_proxies = settings.get_cloudflare_proxies()

    is_cf_peer = ip_in_networks(direct_peer, cloudflare_proxies)
    is_generic_proxy = ip_in_networks(direct_peer, trusted_proxies)

    # 3. Direct untrusted client: DISCARD ALL FORWARDED HEADERS
    if not is_cf_peer and not is_generic_proxy:
        return direct_peer, is_private_ip(direct_peer)

    all_trusted = list(trusted_proxies) + list(cloudflare_proxies)

    # 4. Provider-Specific Trust: Cloudflare Edge Peer
    if is_cf_peer:
        # CF-Connecting-IP takes highest precedence only from verified Cloudflare peer
        cf_ip = headers.get("cf-connecting-ip", "").strip()
        if cf_ip and is_valid_ip(cf_ip):
            return cf_ip, is_private_ip(cf_ip)

        true_client_ip = headers.get("true-client-ip", "").strip()
        if true_client_ip and is_valid_ip(true_client_ip):
            return true_client_ip, is_private_ip(true_client_ip)

    # 5. Generic Trusted Proxy / Cloudflare fallback: Parse X-Forwarded-For backwards
    xff = headers.get("x-forwarded-for", "").strip()
    if xff:
        hops = [h.strip() for h in xff.split(",") if h.strip()]
        # Walk from right (most recent proxy) to left (client origin)
        for hop in reversed(hops):
            if is_valid_ip(hop):
                if not ip_in_networks(hop, all_trusted):
                    return hop, is_private_ip(hop)
        # If all hops are trusted internal proxies, fallback to origin (leftmost)
        for hop in hops:
            if is_valid_ip(hop):
                return hop, is_private_ip(hop)

    # 6. Single-hop X-Real-IP (only if from trusted generic proxy)
    x_real_ip = headers.get("x-real-ip", "").strip()
    if x_real_ip and is_valid_ip(x_real_ip):
        return x_real_ip, is_private_ip(x_real_ip)

    # 7. Fallback to direct peer
    return direct_peer, is_private_ip(direct_peer)


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
