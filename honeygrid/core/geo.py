import requests
from typing import Dict, Any, Optional
from honeygrid.config import settings
from honeygrid.core.fingerprint import is_private_ip

_GEO_CACHE: Dict[str, Dict[str, Any]] = {}

def lookup_ip_geolocation(ip_address: str, fallback_to_public: bool = True) -> Dict[str, Any]:
    """
    Looks up geolocation and ISP/ASN data for a given IP address using ip-api.com.
    Results are cached in-memory to prevent duplicate requests and API rate limits.
    """
    if ip_address in _GEO_CACHE:
        return _GEO_CACHE[ip_address]

    default_geo = {
        "country": "Localhost / Internal Subnet",
        "city": "Private Network",
        "region": "Internal",
        "isp": "Local Loopback / Private Gateway",
        "asn": "N/A",
        "lat": None,
        "lon": None,
        "query_ip": ip_address
    }
    
    if not settings.ENABLE_GEOIP_LOOKUP:
        return default_geo

    target_ip = ip_address
    
    # If the request comes from localhost or a private LAN IP,
    # we can optionally resolve the current external public IP for demonstration/testing
    if is_private_ip(ip_address):
        if not fallback_to_public:
            return default_geo
        target_ip = "" # Querying ip-api.com without an IP returns the public IP of the caller

    try:
        url = f"http://ip-api.com/json/{target_ip}?fields=status,message,country,city,regionName,isp,as,lat,lon,query"
        resp = requests.get(url, timeout=3.5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                res = {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "asn": data.get("as", "Unknown"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "query_ip": data.get("query", ip_address)
                }
                _GEO_CACHE[ip_address] = res
                return res
    except Exception:
        pass

    _GEO_CACHE[ip_address] = default_geo
    return default_geo
