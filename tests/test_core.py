"""Authentication, RBAC, validation, and security tests shared by every project."""
import time

import jwt

from app import DEFAULT_ROLE, ROLES, create_app
from app.core import DEMO_PASSWORD
from tests.base import ADMIN, Base

NEW = {"email": "new.user@example.test", "name": "New User", "password": "Str0ng-Passw0rd"}


class AuthTests(Base):
    def test_health(self):
        self.assertEqual(self.get("/api/health").get_json(), {"status": "ok"})

    def test_register_login_me(self):
        r = self.post("/api/auth/register", json=NEW)
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.get_json()["data"]["role"], DEFAULT_ROLE)
        self.assertNotIn("password", str(r.get_json()))
        tok = self.data(self.login(NEW["email"], NEW["password"]), 200)["token"]
        me = self.data(self.get("/api/auth/me", headers={"Authorization": "Bearer " + tok}), 200)
        self.assertEqual(me["email"], NEW["email"])

    def test_register_validation(self):
        for bad in ({**NEW, "password": "short1"}, {**NEW, "password": "onlylettersonly"}, {**NEW, "email": "not-an-email"}, {**NEW, "name": ""}):
            self.assertEqual(self.post("/api/auth/register", json=bad).status_code, 422, bad)
        self.assertEqual(self.post("/api/auth/register", data="nope", content_type="application/json").status_code, 400)

    def test_duplicate_email_case_insensitive(self):
        self.assertEqual(self.post("/api/auth/register", json=NEW).status_code, 201)
        self.assertEqual(self.post("/api/auth/register", json={**NEW, "email": NEW["email"].upper()}).status_code, 409)

    def test_bad_credentials_are_indistinguishable(self):
        a = self.login(ADMIN, "wrong-password-1")
        b = self.login("nobody@example.test", "wrong-password-1")
        self.assertEqual((a.status_code, b.status_code), (401, 401))
        self.assertEqual(a.get_json(), b.get_json())
        self.assertEqual(self.login("' OR '1'='1", "' OR '1'='1").status_code, 401)

    def test_protected_requires_valid_token(self):
        self.assertEqual(self.get("/api/auth/me").status_code, 401)
        self.assertEqual(self.get("/api/auth/me", headers={"Authorization": "Bearer garbage"}).status_code, 401)
        forged = jwt.encode({"sub": "1", "role": "admin", "jti": "x", "exp": int(time.time()) + 600}, "other-secret-other-secret-other-1234", algorithm="HS256")
        self.assertEqual(self.get("/api/auth/me", headers={"Authorization": "Bearer " + forged}).status_code, 401)
        expired = jwt.encode({"sub": "1", "role": "admin", "jti": "y", "exp": int(time.time()) - 5}, self.app.config["SECRET_KEY"], algorithm="HS256")
        self.assertEqual(self.get("/api/auth/me", headers={"Authorization": "Bearer " + expired}).status_code, 401)

    def test_logout_revokes_token(self):
        self.assertEqual(self.get("/api/auth/me", ADMIN).status_code, 200)
        self.assertEqual(self.post("/api/auth/logout", ADMIN).status_code, 200)
        self.assertEqual(self.get("/api/auth/me", ADMIN).status_code, 401)

    def test_rate_limit_on_login(self):
        app = create_app({**self.app.config, "RATELIMIT_ENABLED": True, "RATELIMIT_LOGIN": 3})
        c = app.test_client()
        codes = [c.post("/api/auth/login", json={"email": "a@b.test", "password": "x"}).status_code for _ in range(5)]
        self.assertEqual(codes, [401, 401, 401, 429, 429])


class UserAdminTests(Base):
    def setUp(self):
        super().setUp()
        self.post("/api/auth/register", json=NEW)
        self.uid = self.data(self.get("/api/users?q=new.user", ADMIN), 200)[0]["id"]

    def test_non_admin_forbidden(self):
        tok = self.data(self.login(NEW["email"], NEW["password"]), 200)["token"]
        self.assertEqual(self.get("/api/users", headers={"Authorization": "Bearer " + tok}).status_code, 403)

    def test_role_change_applies_immediately_and_validates(self):
        self.assertEqual(self.put(f"/api/users/{self.uid}", ADMIN, json={"role": "superuser"}).status_code, 422)
        other = [r for r in ROLES if r != DEFAULT_ROLE][0]
        self.assertEqual(self.data(self.put(f"/api/users/{self.uid}", ADMIN, json={"role": other}), 200)["role"], other)

    def test_deactivated_user_loses_access_and_login(self):
        tok = self.data(self.login(NEW["email"], NEW["password"]), 200)["token"]
        self.assertEqual(self.put(f"/api/users/{self.uid}", ADMIN, json={"active": False}).status_code, 200)
        self.assertEqual(self.get("/api/auth/me", headers={"Authorization": "Bearer " + tok}).status_code, 401)
        self.assertEqual(self.login(NEW["email"], NEW["password"]).status_code, 401)

    def test_admin_cannot_demote_or_disable_self(self):
        me = self.data(self.get("/api/auth/me", ADMIN), 200)["id"]
        self.assertEqual(self.put(f"/api/users/{me}", ADMIN, json={"active": False}).status_code, 409)
        self.assertEqual(self.put(f"/api/users/{me}", ADMIN, json={"role": DEFAULT_ROLE}).status_code, 409)

    def test_reset_password(self):
        self.assertEqual(self.post(f"/api/users/{self.uid}/reset-password", ADMIN, json={"password": "weak"}).status_code, 422)
        self.assertEqual(self.post(f"/api/users/{self.uid}/reset-password", ADMIN, json={"password": "Brand-New-Pass-77"}).status_code, 200)
        self.assertEqual(self.login(NEW["email"], NEW["password"]).status_code, 401)
        self.assertEqual(self.login(NEW["email"], "Brand-New-Pass-77").status_code, 200)

    def test_audit_log_records_events_and_hides_secrets(self):
        rows = self.data(self.get("/api/audit?per_page=100", ADMIN), 200)
        self.assertTrue(any(r["action"] == "register" for r in rows))
        self.assertNotIn("password", str(rows).lower().replace("reset_password", ""))


class HardeningTests(Base):
    def test_security_headers(self):
        r = self.get("/api/health")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["Cache-Control"], "no-store")

    def test_cors_allowlist(self):
        app = create_app({**self.app.config, "CORS_ORIGINS": ["https://ok.example"]})
        c = app.test_client()
        self.assertEqual(c.get("/api/health", headers={"Origin": "https://ok.example"}).headers.get("Access-Control-Allow-Origin"), "https://ok.example")
        self.assertIsNone(c.get("/api/health", headers={"Origin": "https://evil.example"}).headers.get("Access-Control-Allow-Origin"))

    def test_sql_injection_attempts_are_inert(self):
        for q in ("' OR 1=1 --", "x'; DROP TABLE users; --", "%", "_"):
            self.assertEqual(self.get("/api/users", ADMIN, query_string={"q": q}).status_code, 200)
        self.assertEqual(self.get("/api/users?sort=id;DROP TABLE users", ADMIN).status_code, 200)
        self.assertGreaterEqual(self.data(self.get("/api/users", ADMIN), 200).__len__(), 1)

    def test_pagination_and_bad_params(self):
        r = self.get("/api/users?per_page=1", ADMIN).get_json()
        self.assertEqual((r["meta"]["per_page"], len(r["data"])), (1, 1))
        self.assertEqual(self.get("/api/users?page=abc", ADMIN).status_code, 400)

    def test_errors_are_json_and_do_not_leak(self):
        r = self.get("/api/nope", ADMIN)
        self.assertEqual((r.status_code, r.get_json()["error"]["code"]), (404, "not_found"))
        self.assertEqual(self.get("/api/users/99999", ADMIN).status_code, 404)

    def test_static_frontend_and_path_traversal(self):
        for path, code in (("/", 200), ("/config.js", 200), ("/..%2f..%2fapp%2fcore.py", 404)):
            r = self.get(path)
            self.assertEqual(r.status_code, code, path)
            if path == "/":
                self.assertIn(b'id="root"', r.data)
            r.close()

    def test_production_requires_strong_secret(self):
        for secret in (None, "short"):
            with self.assertRaises(RuntimeError):
                create_app({**self.app.config, "APP_ENV": "production", "SECRET_KEY": secret})

    def test_passwords_stored_hashed(self):
        import sqlite3
        row = sqlite3.connect(self.app.config["DATABASE_PATH"]).execute("SELECT password_hash FROM users LIMIT 1").fetchone()[0]
        self.assertTrue(row.startswith("scrypt$"))
        self.assertNotIn(DEMO_PASSWORD, row)
