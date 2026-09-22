import requests
from typing import Dict, Any
from honeygrid.config import settings
from honeygrid.core.fingerprint import is_private_ip

from honeygrid.core.tor import is_tor_exit_node

# Known major datacenter / hosting ASN keywords indicative of cloud scanners, VPNs or proxies
HOSTING_KEYWORDS = [
    "digitalocean", "amazon", "aws", "microsoft", "azure", "google", "ovh",
    "linode", "hetzner", "vultr", "choopa", "m247", "fastly", "cloudflare",
    "leaseweb", "contabo", "datapacket", "scaleway", "alibaba", "oracle"
]

def analyze_ip_threat(ip_address: str, geo_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates threat risk score and connection type for an IP address.
    Categorizes into Tor, Commercial VPN / Datacenter, or Residential / Business.
    Calculates an Adversary Threat Score (0-100%).
    """
    if is_private_ip(ip_address):
        return {
            "threat_score": 5,
            "connection_type": "Localhost / Internal Subnet",
            "is_vpn_proxy": False,
            "is_tor": False,
            "is_datacenter": False,
            "threat_level": "LOW"
        }

    # 1. Real Tor Exit-Node Verification
    is_tor = is_tor_exit_node(ip_address)

    # 2. Network & ASN Keyword Inspection
    isp = geo_data.get("isp", "").lower()
    asn = geo_data.get("asn", "").lower()
    org = geo_data.get("org", "").lower() if "org" in geo_data else ""
    combined_network_str = f"{isp} {asn} {org}"

    is_datacenter = any(kw in combined_network_str for kw in HOSTING_KEYWORDS)
    is_vpn_proxy = is_tor or geo_data.get("is_proxy", False)
    
    # Calculate base threat score
    threat_score = 15  # Base score for touching a deception trap

    if is_tor:
        threat_score = 95
    elif is_vpn_proxy:
        threat_score = 65
    elif is_datacenter:
        threat_score = 50

    threat_score = min(threat_score, 100)


    # Determine connection type badge
    if is_tor:
        conn_type = "Tor Exit Node (Anonymized)"
        threat_level = "CRITICAL"
        threat_score = 95
    elif is_vpn_proxy:
        conn_type = "Commercial VPN / Web Proxy"
        threat_level = "HIGH"
    elif is_datacenter:
        conn_type = "Cloud Datacenter / VPS Scanner"
        threat_level = "HIGH"
    else:
        conn_type = "Residential / Corporate ISP"
        threat_level = "ELEVATED" if threat_score > 30 else "MODERATE"

    return {
        "threat_score": threat_score,
        "connection_type": conn_type,
        "is_vpn_proxy": is_vpn_proxy,
        "is_tor": is_tor,
        "is_datacenter": is_datacenter,
        "threat_level": threat_level
    }
