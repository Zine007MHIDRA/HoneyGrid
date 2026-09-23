import os
import sys
import uuid
import unittest
from unittest.mock import patch, MagicMock
from starlette.testclient import TestClient

# Ensure honeygrid module is discoverable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from honeygrid.config import settings
from honeygrid.core.fingerprint import extract_client_ip
from honeygrid.core.tor import TorDetector
from honeygrid.core.threat_intel import analyze_ip_threat
from honeygrid.core.rate_limit import LoginRateLimiter
from honeygrid.core.containment import block_ip
from honeygrid.database import (
    init_db, add_safe_ip, remove_safe_ip, is_safe_ip,
    record_incident, list_incidents, list_audit_logs,
    get_user_by_email, create_user
)
from honeygrid.models import IncidentEvent, User
from honeygrid.alerts.discord import send_discord_signup_alert
from honeygrid.server.listener import app, process_incident_async


class TestAdversarialHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)

    def test_untrusted_peer_spoofing_rejected(self):
        """Untrusted TCP peers attempting to spoof forwarded or Cloudflare headers must be ignored."""
        req = MagicMock()
        req.client.host = "93.184.216.34"
        req.headers = {
            "x-forwarded-for": "8.8.8.8, 1.1.1.1",
            "cf-connecting-ip": "1.2.3.4",
            "true-client-ip": "5.6.7.8",
            "x-real-ip": "9.9.9.9"
        }
        extracted, is_local = extract_client_ip(req, trusted_proxies=["127.0.0.1"])
        self.assertEqual(extracted, "93.184.216.34", "Direct socket IP must be used when peer is untrusted!")
        self.assertFalse(is_local)

    def test_generic_trusted_proxy_multi_hop_xff(self):
        """Trusted reverse proxy with multi-hop X-Forwarded-For should parse right-to-left untrusted client."""
        req = MagicMock()
        req.client.host = "10.0.0.1"
        req.headers = {
            "x-forwarded-for": "93.184.216.34, 10.0.0.2"
        }
        extracted, _ = extract_client_ip(req, trusted_proxies=["10.0.0.1", "10.0.0.2"])
        self.assertEqual(extracted, "93.184.216.34")

    def test_generic_trusted_proxy_cannot_spoof_cloudflare(self):
        """Generic trusted proxy (not in Cloudflare CIDRs) cannot assert CF-Connecting-IP."""
        req = MagicMock()
        req.client.host = "10.0.0.1"
        req.headers = {
            "cf-connecting-ip": "1.2.3.4",
            "x-forwarded-for": "93.184.216.99"
        }
        extracted, _ = extract_client_ip(req, trusted_proxies=["10.0.0.1"], cloudflare_proxies=["173.245.48.0/20"])
        self.assertEqual(extracted, "93.184.216.99", "Generic proxy cannot spoof Cloudflare headers!")

    def test_cloudflare_trusted_proxy_accepts_cf_connecting_ip(self):
        """Direct peer from Cloudflare IP range must be granted CF-Connecting-IP trust."""
        req = MagicMock()
        req.client.host = "173.245.48.5"
        req.headers = {
            "cf-connecting-ip": "93.184.216.88"
        }
        extracted, _ = extract_client_ip(req, cloudflare_proxies=["173.245.48.0/20"])
        self.assertEqual(extracted, "93.184.216.88")

    def test_tor_detector_detection_and_threat_scoring(self):
        """TorDetector should detect exit nodes and assign CRITICAL threat level."""
        detector = TorDetector()
        test_exit_node = "185.220.101.5"
        detector._exit_nodes.add(test_exit_node)
        self.assertTrue(detector.is_tor_exit_node(test_exit_node))
        self.assertFalse(detector.is_tor_exit_node("8.8.8.8"))

        with patch("honeygrid.core.threat_intel.is_tor_exit_node", return_value=True):
            threat = analyze_ip_threat(test_exit_node, {"country": "Germany", "isp": "Tor Relay"})
            self.assertTrue(threat.get("is_tor"))
            self.assertEqual(threat.get("threat_level"), "CRITICAL")
            self.assertGreaterEqual(threat.get("threat_score"), 90)

    def test_database_backed_rate_limiter_persistence(self):
        """LoginRateLimiter strikes must persist across independent instances."""
        test_ip = f"192.0.2.{uuid.uuid4().hex[:4]}"
        limiter1 = LoginRateLimiter(max_attempts=3, window_seconds=120, lockout_seconds=120)
        limiter2 = LoginRateLimiter(max_attempts=3, window_seconds=120, lockout_seconds=120)

        self.assertEqual(limiter1.record_failure(test_ip), 1)
        self.assertEqual(limiter2.record_failure(test_ip), 2)
        self.assertEqual(limiter1.record_failure(test_ip), 3)

        is_locked, remaining = limiter2.is_locked(test_ip)
        self.assertTrue(is_locked)
        self.assertGreater(remaining, 0)

        limiter1.record_success(test_ip)
        is_locked_after, _ = limiter2.is_locked(test_ip)
        self.assertFalse(is_locked_after)

    def test_safelist_immunity_from_rate_limit(self):
        """Safe-listed IPs must be immune from brute-force rate limit lockout."""
        safe_ip = "192.0.2.200"
        add_safe_ip(safe_ip, label="Admin Office", added_by="admin@test.corp")
        limiter = LoginRateLimiter(max_attempts=2, window_seconds=60, lockout_seconds=60)

        limiter.record_failure(safe_ip)
        limiter.record_failure(safe_ip)
        limiter.record_failure(safe_ip)

        is_locked, remaining = limiter.is_locked(safe_ip)
        self.assertFalse(is_locked, "Safe-listed IP must never be locked out!")
        self.assertEqual(remaining, 0)

    def test_safelist_immunity_from_containment(self):
        """Safe-listed IPs cannot be contained or isolated."""
        safe_ip = "192.0.2.201"
        add_safe_ip(safe_ip, label="SOC Gateway", added_by="admin@test.corp")

        result = block_ip(safe_ip)
        self.assertFalse(result.get("applied"))
        self.assertIn("Safe List", result.get("message", ""))

    def test_incident_processing_resilience_on_geoip_failure(self):
        """Failure in GeoIP or Threat Intel must not abort incident recording."""
        random_token = f"tok_{uuid.uuid4().hex[:8]}"
        with patch("honeygrid.server.listener.lookup_ip_geolocation", side_effect=Exception("GeoIP API Down")):
            with patch("honeygrid.server.listener.send_discord_alert", side_effect=Exception("Discord Webhook 500")):
                process_incident_async(
                    token_id=random_token,
                    raw_ip="93.184.216.44",
                    is_local=False,
                    client_tool="Adversary-Tool/1.0",
                    user_agent="Adversary-UA",
                    http_method="GET",
                    request_path=f"/t/{random_token}",
                    query_params="",
                    headers_dict={"user-agent": "Adversary-UA"}
                )

        incidents = list_incidents(is_admin=True, limit=5)
        matched = [i for i in incidents if i.token_id == random_token]
        self.assertEqual(len(matched), 1, "Incident must be recorded even if GeoIP and Discord fail!")
        self.assertEqual(matched[0].attacker_ip, "93.184.216.44")

    def test_audit_logs_endpoint_access(self):
        """Audit logs can be retrieved by authenticated operators."""
        test_email = f"audit_admin_{uuid.uuid4().hex[:6]}@test.corp"
        user = create_user(email=test_email, password_hash="hash", salt="salt", role="admin")
        
        res_unauth = self.client.get("/api/audit-logs")
        self.assertEqual(res_unauth.status_code, 401)

        from honeygrid.database import create_session
        sess = create_session(user.id, expire_hours=1)
        self.client.cookies.set(settings.SESSION_COOKIE_NAME, sess)

        res = self.client.get("/api/audit-logs?limit=10")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("status"), "success")
        self.assertIsInstance(data.get("audit_logs"), list)
        self.assertGreater(len(data.get("audit_logs")), 0)

    def test_discord_signup_webhook_dispatch(self):
        """send_discord_signup_alert formats payload correctly and delivers to webhook."""
        dummy_user = User(
            id=f"usr_{uuid.uuid4().hex[:8]}",
            email=f"operator_{uuid.uuid4().hex[:6]}@corp.internal",
            role="user",
            created_at="2026-09-22T20:46:00Z"
        )
        
        with patch("requests.post") as mock_post:
            mock_post.return_value.status_code = 204
            
            res = send_discord_signup_alert(
                user=dummy_user,
                client_ip="203.0.113.19",
                user_agent="Mozilla/5.0 TestBrowser",
                client_tool="Custom Browser",
                geo_data={"country": "Morocco", "city": "Rabat", "isp": "IAM", "asn": "AS36903"}
            )
            
            self.assertTrue(res)
            self.assertTrue(mock_post.called)
            called_args, called_kwargs = mock_post.call_args
            called_url = called_args[0] if called_args else called_kwargs.get("url")
            self.assertIn("discord.com/api/webhooks", called_url)
            
            import json
            payload = json.loads(called_kwargs.get("data", "{}"))
            self.assertEqual(payload["username"], "HoneyGrid Sentinel • IAM")
            embed = payload["embeds"][0]
            self.assertIn(dummy_user.email, embed["title"])
            field_names = [f["name"] for f in embed["fields"]]
            self.assertTrue(any("Operator Account" in n for n in field_names))
            self.assertTrue(any("Network Origin" in n for n in field_names))
            self.assertTrue(any("Client Environment" in n for n in field_names))
            self.assertTrue(any("Security Attestation" in n for n in field_names))

    def test_html_templates_javascript_syntax(self):
        """Validates that all inline <script> tags in dashboard.html and login.html compile without SyntaxErrors."""
        import re
        import subprocess
        from pathlib import Path
        
        templates_dir = Path(__file__).resolve().parent.parent / "honeygrid" / "server" / "templates"
        script_pattern = re.compile(r"<script(?:\s+[^>]*)?>(.*?)</script>", re.DOTALL | re.IGNORECASE)
        
        for html_file in templates_dir.glob("*.html"):
            content = html_file.read_text(encoding="utf-8")
            scripts = script_pattern.findall(content)
            for idx, script in enumerate(scripts):
                cleaned = script.strip()
                if not cleaned:
                    continue
                # Replace Jinja placeholders
                sanitized = re.sub(r"\{\{.*?\}\}", "'dummy'", cleaned)
                try:
                    proc = subprocess.run(
                        ["node", "--check", "-"],
                        input=sanitized,
                        text=True,
                        encoding="utf-8",
                        capture_output=True
                    )
                    if proc.returncode != 0:
                        self.fail(f"JavaScript SyntaxError in {html_file.name} (script #{idx + 1}): {proc.stderr}")
                except FileNotFoundError:
                    # Node not installed in minimal CI container; check for unescaped raw newlines in string literals
                    self.assertNotIn("join('\n')", sanitized)


if __name__ == "__main__":
    unittest.main()

