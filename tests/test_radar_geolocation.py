import unittest
from honeygrid.core.geo import (
    lookup_ip_geolocation,
    extract_geo_from_headers,
    COUNTRY_CENTROIDS
)
from honeygrid.models import IncidentEvent
from honeygrid.database import list_incidents

class TestRadarGeolocation(unittest.TestCase):
    def test_vercel_edge_header_extraction(self):
        """Vercel edge geolocation headers must resolve with 0ms latency without network calls."""
        headers = {
            "x-vercel-ip-latitude": "33.58988",
            "x-vercel-ip-longitude": "-7.60386",
            "x-vercel-ip-city": "Casablanca",
            "x-vercel-ip-country": "MA",
            "x-vercel-ip-as-number": "36903"
        }
        res = extract_geo_from_headers(headers, "105.157.10.162")
        self.assertIsNotNone(res)
        self.assertAlmostEqual(res["lat"], 33.58988)
        self.assertAlmostEqual(res["lon"], -7.60386)
        self.assertEqual(res["country"], "Morocco")
        self.assertEqual(res["city"], "Casablanca")
        self.assertEqual(res["asn"], "AS36903")
        self.assertEqual(res["source"], "edge_headers")

    def test_cloudflare_edge_header_extraction(self):
        """Cloudflare edge headers must resolve accurately."""
        headers = {
            "cf-iplatitude": "48.8566",
            "cf-iplongitude": "2.3522",
            "cf-ipcity": "Paris",
            "cf-ipcountry": "FR"
        }
        res = extract_geo_from_headers(headers, "194.26.29.112")
        self.assertIsNotNone(res)
        self.assertAlmostEqual(res["lat"], 48.8566)
        self.assertAlmostEqual(res["lon"], 2.3522)
        self.assertEqual(res["country"], "France")
        self.assertEqual(res["city"], "Paris")

    def test_lookup_with_headers_integration(self):
        """lookup_ip_geolocation must prioritize edge headers over network queries."""
        headers = {
            "x-vercel-ip-latitude": "33.8947",
            "x-vercel-ip-longitude": "-6.30649",
            "x-vercel-ip-city": "Tiflet",
            "x-vercel-ip-country": "MA",
            "x-vercel-ip-as-number": "36903"
        }
        res = lookup_ip_geolocation("105.157.10.162", headers=headers)
        self.assertEqual(res["country"], "Morocco")
        self.assertEqual(res["city"], "Tiflet")
        self.assertAlmostEqual(res["lat"], 33.8947)
        self.assertAlmostEqual(res["lon"], -6.30649)

    def test_public_ip_never_tagged_localhost(self):
        """Public IPs must never be categorized as Localhost / Internal Subnet."""
        # Using a public IP with no headers
        res = lookup_ip_geolocation("105.157.10.162")
        self.assertNotEqual(res["country"], "Localhost / Internal Subnet")
        self.assertNotEqual(res["isp"], "Local Loopback / Private Gateway")
        self.assertIsNotNone(res["lat"])
        self.assertIsNotNone(res["lon"])

    def test_country_centroids_present(self):
        """Major threat origins must have centroid coordinates."""
        for code in ["MA", "US", "FR", "DE", "GB", "CN", "RU"]:
            self.assertIn(code, COUNTRY_CENTROIDS)
            lat, lon = COUNTRY_CENTROIDS[code]
            self.assertIsInstance(lat, (float, int))
            self.assertIsInstance(lon, (float, int))

if __name__ == "__main__":
    unittest.main()
