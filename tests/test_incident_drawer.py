import os
import sys
import uuid
import unittest
from datetime import datetime, timezone
from starlette.testclient import TestClient

# Ensure honeygrid module is discoverable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from honeygrid.config import settings
from honeygrid.database import (
    init_db, create_user, create_session, save_token, record_incident,
    update_incident_telemetry, get_incident, list_incidents
)
from honeygrid.models import IncidentEvent, Token, BrowserTelemetry
from honeygrid.server.listener import app


def _make_user(role="user"):
    return create_user(email=f"drawer_{uuid.uuid4().hex[:8]}@test.corp", password_hash="hash", salt="salt", role=role)

def _make_token(owner):
    token = Token(
        id=f"tok_{uuid.uuid4().hex[:10]}", token_type="web", label="Drawer Test",
        created_at=datetime.now(timezone.utc).isoformat(), owner_id=owner.id, owner_email=owner.email
    )
    return save_token(token)

def _record(token_id, ip, score=15, **extra):
    return record_incident(IncidentEvent(token_id=token_id, attacker_ip=ip, threat_score=score, **extra))

def _random_public_ip():
    b = uuid.uuid4().bytes
    return f"93.{b[0]}.{b[1]}.{b[2] % 250 + 1}"


class TestIncidentDrawerAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def _client_for(self, user):
        client = TestClient(app)
        client.cookies.set(settings.SESSION_COOKIE_NAME, create_session(user.id, expire_hours=1))
        return client

    def test_detail_requires_session(self):
        res = TestClient(app).get("/api/incidents/1")
        self.assertEqual(res.status_code, 401)

    def test_detail_hidden_from_other_tenant(self):
        owner, outsider = _make_user(), _make_user()
        token = _make_token(owner)
        incident_id = _record(token.id, _random_public_ip())

        self.assertEqual(self._client_for(owner).get(f"/api/incidents/{incident_id}").status_code, 200)
        self.assertEqual(self._client_for(outsider).get(f"/api/incidents/{incident_id}").status_code, 404)
        self.assertEqual(self._client_for(owner).get("/api/incidents/999999999").status_code, 404)

    def test_detail_returns_timeline_summary_and_signals(self):
        admin = _make_user(role="admin")
        token_a, token_b = _make_token(admin), _make_token(admin)
        ip = _random_public_ip()
        ids = [
            _record(token_a.id, ip, score=15),
            _record(token_b.id, ip, score=65, is_vpn_proxy=True, client_tool="cURL CLI"),
            _record(token_a.id, ip, score=15),
        ]
        _record(token_a.id, _random_public_ip())  # unrelated attacker must not leak into the timeline

        res = self._client_for(admin).get(f"/api/incidents/{ids[1]}")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["incident"]["id"], ids[1])
        self.assertEqual([t["id"] for t in data["timeline"]], ids, "timeline must be this IP only, oldest first")
        self.assertEqual(data["summary"]["hit_count"], 3)
        self.assertEqual(data["summary"]["tokens_touched"], [token_a.id, token_b.id])
        self.assertFalse(data["summary"]["is_safelisted"])

        signals = {s["key"]: s["active"] for s in data["signals"]}
        self.assertTrue(signals["vpn"])
        self.assertTrue(signals["scripted"])
        self.assertFalse(signals["tor"])

    def test_list_filters(self):
        admin = _make_user(role="admin")
        token = _make_token(admin)
        ip = _random_public_ip()
        _record(token.id, ip, score=15)
        high_id = _record(token.id, ip, score=95, is_tor=True)

        client = self._client_for(admin)
        by_ip = client.get(f"/api/incidents?q={ip}").json()
        self.assertEqual({i["attacker_ip"] for i in by_ip}, {ip})
        self.assertEqual(len(by_ip), 2)

        high = client.get(f"/api/incidents?q={ip}&min_score=50").json()
        self.assertEqual([i["id"] for i in high], [high_id])


class TestTelemetryCorrelation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def test_concurrent_visitors_keep_their_own_telemetry(self):
        owner = _make_user()
        token = _make_token(owner)
        ip_a, ip_b = _random_public_ip(), _random_public_ip()
        id_a = _record(token.id, ip_a)
        id_b = _record(token.id, ip_b)  # newest incident for the token belongs to B

        update_incident_telemetry(token.id, BrowserTelemetry(gpu_renderer="GPU-A", platform="Win32"), client_ip=ip_a)
        update_incident_telemetry(token.id, BrowserTelemetry(gpu_renderer="GPU-B"), client_ip=ip_b)

        a = get_incident(id_a, is_admin=True)
        b = get_incident(id_b, is_admin=True)
        self.assertEqual(a.gpu_renderer, "GPU-A")
        self.assertEqual(a.client_platform, "Win32")
        self.assertEqual(b.gpu_renderer, "GPU-B")

    def test_telemetry_arriving_before_incident_is_merged(self):
        owner = _make_user()
        token = _make_token(owner)
        ip = _random_public_ip()

        matched = update_incident_telemetry(token.id, BrowserTelemetry(gpu_renderer="Early GPU", cpu_cores=8), client_ip=ip)
        self.assertIsNone(matched, "no incident exists yet, payload must be parked")

        incident_id = _record(token.id, ip)
        incident = get_incident(incident_id, is_admin=True)
        self.assertEqual(incident.gpu_renderer, "Early GPU")
        self.assertEqual(incident.cpu_cores, 8)

    def test_telemetry_endpoint_stays_public(self):
        owner = _make_user()
        token = _make_token(owner)
        res = TestClient(app).post(f"/t/{token.id}/telemetry", json={"gpu_renderer": "X"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"status": "received"})


class TestLandingAndTheme(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def test_root_serves_landing_to_anonymous_browsers(self):
        res = TestClient(app).get("/", headers={"accept": "text/html"}, follow_redirects=False)
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/html", res.headers["content-type"])
        self.assertIn("/login", res.text)
        self.assertNotIn("/t/", res.text, "landing page must not advertise canary paths")

    def test_root_redirects_operators_to_dashboard(self):
        client = TestClient(app)
        client.cookies.set(settings.SESSION_COOKIE_NAME, create_session(_make_user().id, expire_hours=1))
        res = client.get("/", headers={"accept": "text/html"}, follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertEqual(res.headers["location"], "/dashboard")

    def test_root_json_for_non_browsers(self):
        res = TestClient(app).get("/", headers={"accept": "application/json"})
        self.assertEqual(res.json().get("status"), "active")

    def test_theme_stylesheet(self):
        res = TestClient(app).get("/ui/theme.css")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/css", res.headers["content-type"])


if __name__ == "__main__":
    unittest.main()
