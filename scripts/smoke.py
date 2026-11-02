"""HTTP smoke test against a running server: python scripts/smoke.py http://127.0.0.1:8000 [email]"""
import json
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8000"
EMAIL = sys.argv[2] if len(sys.argv) > 2 else "admin@demo.test"
PASSWORD = "Demo-Pass-2026!"


def call(method, path, body=None, token=None):
    req = urllib.request.Request(BASE + path, method=method, data=json.dumps(body).encode() if body else None,
                                 headers={"Content-Type": "application/json", **({"Authorization": "Bearer " + token} if token else {})})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


checks = []
def check(name, ok):
    checks.append(ok)
    print(("PASS " if ok else "FAIL ") + name)

check("health", call("GET", "/api/health")[0] == 200)
check("index page served", b'id="root"' in call("GET", "/")[1])
check("unauthenticated stats rejected", call("GET", "/api/stats")[0] == 401)
check("bad password rejected", call("POST", "/api/auth/login", {"email": EMAIL, "password": "wrong-password-1"})[0] == 401)
status, raw = call("POST", "/api/auth/login", {"email": EMAIL, "password": PASSWORD})
token = json.loads(raw)["data"]["token"] if status == 200 else None
check("login", status == 200)
check("stats with token", call("GET", "/api/stats", token=token)[0] == 200)
check("logout", call("POST", "/api/auth/logout", token=token)[0] == 200)
check("token revoked after logout", call("GET", "/api/auth/me", token=token)[0] == 401)
sys.exit(0 if all(checks) else 1)
