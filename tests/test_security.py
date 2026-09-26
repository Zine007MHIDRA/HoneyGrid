import os
import sys
import json
import uuid
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock
from starlette.testclient import TestClient

# Ensure honeygrid module is discoverable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from honeygrid.config import settings
from honeygrid.database import (
    init_db, create_user, create_session, save_token, record_incident, get_user_by_email,
    list_incidents, seed_admin_from_env
)
from honeygrid.models import IncidentEvent, Token
from honeygrid.core.auth import generate_captcha, hash_password, encode_password_hash
from honeygrid.core.rate_limit import login_limiter, account_limiter, register_limiter, captcha_limiter
from honeygrid.core import containment
from honeygrid.server.listener import app

LOCAL_IP = "127.0.0.1"  # what TestClient connections resolve to


def _email(prefix="sec"):
    return f"{prefix}_{uuid.uuid4().hex[:10]}@test.corp"

def _user(role="user", password=None):
    email = _email()
    if password:
        pw_hash, salt = hash_password(password)
    else:
        pw_hash, salt = "hash", "salt"
    return create_user(email=email, password_hash=pw_hash, salt=salt, role=role)

def _client(user=None):
    client = TestClient(app)
    if user:
        client.cookies.set(settings.SESSION_COOKIE_NAME, create_session(user.id, expire_hours=1))
    return client

def _token(owner):
    t = Token(id=f"tok_{uuid.uuid4().hex[:10]}", token_type="web", label="Security Test",
              created_at=datetime.now(timezone.utc).isoformat(), owner_id=owner.id, owner_email=owner.email)
    return save_token(t)

def _captcha():
    code, svg, token = generate_captcha(settings.HONEYGRID_SECRET_KEY)
    return code, token

def _reset_limits():
    for limiter in (login_limiter, register_limiter, captcha_limiter):
        limiter.record_success(LOCAL_IP)


class SecurityTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        _reset_limits()


class TestContainment(SecurityTestCase):
    def test_rejects_non_public_or_malformed_addresses(self):
        admin_client = _client(_user(role="admin"))
        for bad in ["1.2.3.4 & whoami", "0.0.0.0/0", "any", "10.0.0.1", "127.0.0.1", "224.0.0.1", "", None]:
            res = admin_client.post("/api/contain/isolate", json={"ip": bad})
            self.assertEqual(res.status_code, 400, f"{bad!r} must be rejected")
            self.assertNotIn("command", res.json())

    def test_operator_can_only_isolate_their_own_attackers(self):
        operator = _user()
        token = _token(operator)
        record_incident(IncidentEvent(token_id=token.id, attacker_ip="8.8.4.4", threat_score=70))
        client = _client(operator)

        denied = client.post("/api/contain/isolate", json={"ip": "1.1.1.1"})
        self.assertEqual(denied.status_code, 403)

        with patch.object(containment.sys, "platform", "win32"), \
                patch("honeygrid.core.containment.subprocess.run", return_value=MagicMock(returncode=0, stdout="", stderr="")) as run:
            allowed = client.post("/api/contain/isolate", json={"ip": "8.8.4.4"})
        self.assertEqual(allowed.status_code, 200)
        self.assertTrue(allowed.json().get("applied"))
        args, kwargs = run.call_args
        self.assertIsInstance(args[0], list, "netsh must be invoked with an argument list")
        self.assertFalse(kwargs.get("shell"), "shell must never be used")
        self.assertIn("remoteip=8.8.4.4", args[0])


class TestCanary(SecurityTestCase):
    def test_malformed_token_is_not_reflected(self):
        res = TestClient(app).get('/t/%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E', headers={"accept": "text/html"})
        self.assertEqual(res.status_code, 401)
        self.assertNotIn("onerror", res.text)
        self.assertEqual(res.headers["content-type"], "application/json")

    def test_decoy_page_embeds_token_safely_with_headers(self):
        with patch("honeygrid.server.listener.process_incident_async"):
            res = TestClient(app).get("/t/tok_safe_123", headers={"accept": "text/html"})
        self.assertEqual(res.status_code, 401)
        self.assertIn('const tokenId = "tok_safe_123";', res.text)
        self.assertIn("default-src 'self'", res.headers.get("content-security-policy", ""))
        self.assertEqual(res.headers.get("x-content-type-options"), "nosniff")

    def test_session_cookies_are_never_stored_with_incidents(self):
        owner = _user()
        token = _token(owner)
        with patch("honeygrid.server.listener.lookup_ip_geolocation", return_value={}), \
                patch("honeygrid.server.listener.send_discord_alert"):
            TestClient(app).get(f"/t/{token.id}", headers={
                "accept": "text/html",
                "cookie": "honeygrid_session=hgs_TOP_SECRET_VALUE; _ga=GA1.2",
                "authorization": "Bearer ALSO_SECRET",
            })
        stored = [i for i in list_incidents(is_admin=True, limit=50) if i.token_id == token.id]
        self.assertEqual(len(stored), 1)
        dumped = json.dumps(stored[0].raw_headers)
        self.assertNotIn("TOP_SECRET", dumped)
        self.assertNotIn("ALSO_SECRET", dumped)
        self.assertEqual(stored[0].raw_headers["cookie"], "[redacted: honeygrid_session, _ga]")


class TestAdminAndRegistration(SecurityTestCase):
    def _register(self, client, email, password="a-long-enough-password"):
        code, token = _captcha()
        return client.post("/api/auth/register", json={
            "email": email, "password": password, "captcha_answer": code, "captcha_token": token
        })

    def test_registration_never_grants_admin(self):
        admin_email = _email("reserved_admin")
        with patch.object(settings, "ADMIN_EMAIL", admin_email):
            res = self._register(TestClient(app), admin_email)
            self.assertEqual(res.status_code, 400, "the configured admin address can't be registered")
            _reset_limits()
            email = _email("newuser")
            res = self._register(TestClient(app), email)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["user"]["role"], "user")
        self.assertIn("samesite=strict", res.headers.get("set-cookie", "").lower())
        self.assertIn("httponly", res.headers.get("set-cookie", "").lower())

    def test_short_passwords_are_refused(self):
        res = self._register(TestClient(app), _email(), password="short-pw")
        self.assertEqual(res.status_code, 400)

    def test_admin_is_seeded_from_environment(self):
        admin_email = _email("seeded_admin")
        with patch.object(settings, "ADMIN_EMAIL", admin_email), \
                patch.object(settings, "ADMIN_PASSWORD_HASH", encode_password_hash("seeded admin password")):
            seed_admin_from_env()
        user = get_user_by_email(admin_email)
        self.assertIsNotNone(user)
        self.assertTrue(user.is_admin)

        code, token = _captcha()
        res = TestClient(app).post("/api/auth/login", json={
            "email": admin_email, "password": "seeded admin password", "captcha_answer": code, "captcha_token": token
        })
        self.assertEqual(res.status_code, 200)

    def test_hardcoded_admin_email_no_longer_grants_admin(self):
        from honeygrid.models import User
        self.assertFalse(User(id="x", email="zine.mhidra@gmail.com", role="user", created_at="now").is_admin)


class TestSafeListAndAudit(SecurityTestCase):
    def test_safe_list_is_per_operator(self):
        a, b = _user(), _user()
        client_a, client_b = _client(a), _client(b)
        self.assertEqual(client_a.post("/api/safelist/add", json={"ip": "203.0.113.50", "label": "A office"}).status_code, 200)

        b_view = client_b.get("/api/safelist").json()["safe_ips"]
        self.assertNotIn("203.0.113.50", [e["ip"] for e in b_view])
        self.assertEqual(client_b.post("/api/safelist/remove", json={"ip": "203.0.113.50"}).status_code, 404)
        self.assertIn("203.0.113.50", [e["ip"] for e in client_a.get("/api/safelist").json()["safe_ips"]])

        self.assertEqual(client_a.post("/api/safelist/add", json={"ip": "not-an-ip"}).status_code, 400)
        self.assertEqual(client_a.post("/api/safelist/remove", json={"ip": "203.0.113.50"}).status_code, 200)

    def test_audit_log_is_scoped_for_operators(self):
        operator = _user()
        client = _client(operator)
        client.post("/api/safelist/add", json={"ip": "203.0.113.51"})
        rows = client.get("/api/audit-logs?limit=500").json()["audit_logs"]
        self.assertTrue(rows)
        self.assertTrue(all(r["actor"].lower() == operator.email for r in rows), "operators only see their own events")
        self.assertLessEqual(len(client.get("/api/audit-logs?limit=-1").json()["audit_logs"]), 1)


class TestBruteForce(SecurityTestCase):
    def setUp(self):
        super().setUp()
        self.password = "correct horse battery staple"
        self.user = _user(password=self.password)
        account_limiter.record_success(self.user.email)

    def _login(self, password, code=None, token=None):
        if code is None:
            code, token = _captcha()
        return TestClient(app).post("/api/auth/login", json={
            "email": self.user.email, "password": password, "captcha_answer": code, "captcha_token": token
        })

    def test_captcha_is_single_use_and_not_in_markup(self):
        code, token = _captcha()
        self.assertEqual(self._login("wrong password", code, token).status_code, 401)
        replay = self._login(self.password, code, token)
        self.assertEqual(replay.status_code, 400, "a used captcha token must be rejected")
        svg = TestClient(app).get("/api/auth/captcha").json()["captcha_svg"]
        self.assertNotIn("<text", svg)

    def test_account_locks_across_rotating_ips_without_counting_down(self):
        for _ in range(10):
            login_limiter.record_success(LOCAL_IP)  # simulate a fresh IP for every guess
            res = self._login("wrong password")
            self.assertEqual(res.status_code, 401)
            self.assertNotIn("remaining", res.json()["message"].lower())
        login_limiter.record_success(LOCAL_IP)
        locked = self._login(self.password)
        self.assertEqual(locked.status_code, 429, "the account itself must lock, even for the right password")
        account_limiter.record_success(self.user.email)
        login_limiter.record_success(LOCAL_IP)
        self.assertEqual(self._login(self.password).status_code, 200)


class TestHeadersAndSecrets(SecurityTestCase):
    def test_sensitive_responses_are_not_cached_or_indexed(self):
        self.assertEqual(TestClient(app).get("/api/auth/me").headers.get("cache-control"), "no-store")
        login = TestClient(app).get("/login", headers={"accept": "text/html"})
        self.assertIn("noindex", login.headers.get("x-robots-tag", ""))

    def test_no_secrets_committed_in_config(self):
        source = (Path(__file__).resolve().parent.parent / "honeygrid" / "config.py").read_text(encoding="utf-8")
        self.assertNotIn("discord.com/api/webhooks", source)
        self.assertNotIn("hg-sentinel-master-secret-key", source)
        self.assertNotIn("@gmail.com", source)


if __name__ == "__main__":
    unittest.main()
