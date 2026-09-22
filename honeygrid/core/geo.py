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
        # Use HTTPS geolocation provider
        provider_url = settings.GEOIP_API_URL.format(ip=target_ip)
        resp = requests.get(provider_url, timeout=3.0, headers={"User-Agent": "HoneyGrid-Sentinel/2.0"})
        if resp.status_code == 200:
            data = resp.json()
            # Support both freeipapi and standard geo formats
            country = data.get("countryName") or data.get("country") or "Unknown"
            city = data.get("cityName") or data.get("city") or "Unknown"
            region = data.get("regionName") or data.get("region") or "Unknown"
            isp = data.get("asnOrganization") or data.get("isp") or "Unknown"
            asn_raw = data.get("asn") or data.get("as") or "N/A"
            asn = f"AS{asn_raw}" if str(asn_raw).isdigit() else str(asn_raw)
            lat = data.get("latitude") if "latitude" in data else data.get("lat")
            lon = data.get("longitude") if "longitude" in data else data.get("lon")
            query = data.get("ipAddress") or data.get("query") or ip_address
            is_proxy = data.get("isProxy", False)

            res = {
                "country": country,
                "city": city,
                "region": region,
                "isp": isp,
                "asn": asn,
                "lat": float(lat) if lat is not None else None,
                "lon": float(lon) if lon is not None else None,
                "query_ip": query,
                "is_proxy": is_proxy
            }
            _GEO_CACHE[ip_address] = res
            return res
    except Exception:
        pass

    _GEO_CACHE[ip_address] = default_geo
    return default_geo
