import os
import tempfile
import unittest

from app import create_app
from app.core import DEMO_PASSWORD
from app.seed import seed

ADMIN = "admin@demo.test"


class Base(unittest.TestCase):
    config = {}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        cfg = {"TESTING": True, "DATABASE_PATH": os.path.join(self.tmp.name, "t.db"), "RATELIMIT_ENABLED": False,
               "SECRET_KEY": "test-secret-key-test-secret-key-123456", **self.config}
        self.app = create_app(cfg)
        seed(self.app.config["DATABASE_PATH"])
        self.c = self.app.test_client()
        self._tok = {}

    def tearDown(self):
        self.tmp.cleanup()

    def login(self, email, pw=DEMO_PASSWORD):
        return self.c.post("/api/auth/login", json={"email": email, "password": pw})

    def tok(self, email):
        if email not in self._tok:
            r = self.login(email)
            self.assertEqual(r.status_code, 200, r.get_json())
            self._tok[email] = r.get_json()["data"]["token"]
        return self._tok[email]

    def req(self, method, path, email=None, json=None, headers=None, **kw):
        h = dict(headers or {})
        if email:
            h["Authorization"] = "Bearer " + self.tok(email)
        return self.c.open(path, method=method, headers=h, json=json, **kw)

    def get(self, path, email=None, **kw):
        return self.req("GET", path, email, **kw)

    def post(self, path, email=None, json=None, **kw):
        return self.req("POST", path, email, json=json, **kw)

    def put(self, path, email=None, json=None, **kw):
        return self.req("PUT", path, email, json=json, **kw)

    def delete(self, path, email=None, **kw):
        return self.req("DELETE", path, email, **kw)

    def data(self, r, status=None):
        if status is not None:
            self.assertEqual(r.status_code, status, r.get_json())
        return r.get_json().get("data")
