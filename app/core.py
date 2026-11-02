"""Shared core: config, SQLite access, migrations, JWT auth, RBAC, validation, generic CRUD."""
import functools, hashlib, hmac, logging, os, re, secrets, sqlite3, time, uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import jwt
from flask import Flask, g, jsonify, request, send_from_directory, current_app
from werkzeug.exceptions import HTTPException

EMAIL_RE = r"[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}"
DEMO_PASSWORD = "Demo-Pass-2026!"  # local demo data only


class ApiError(Exception):
    def __init__(self, status, code, message, details=None):
        super().__init__(message)
        self.status, self.code, self.message, self.details = status, code, message, details


def err(status, code, message, details=None):
    raise ApiError(status, code, message, details)


class Bad(ValueError):
    """Validation message safe to show to clients."""


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ---------- database ----------
def connect(path):
    conn = sqlite3.connect(path, isolation_level=None, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def db():
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE_PATH"])
    return g.db


@contextmanager
def tx():
    """Serialised write transaction (BEGIN IMMEDIATE) that rolls back on any error."""
    c = db()
    if c.in_transaction:
        yield c
        return
    c.execute("BEGIN IMMEDIATE")
    try:
        yield c
        c.execute("COMMIT")
    except BaseException:
        c.execute("ROLLBACK")
        raise


def migrate(db_path, mig_dir):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path)
    conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations(name TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')))")
    done = {r[0] for r in conn.execute("SELECT name FROM schema_migrations")}
    applied = []
    for f in sorted(Path(mig_dir).glob("*.sql")):
        if f.name not in done:
            conn.executescript(f.read_text())
            conn.execute("INSERT INTO schema_migrations(name) VALUES(?)", (f.name,))
            applied.append(f.name)
    conn.close()
    return applied


def audit(action, entity, entity_id=None, detail=None):
    uid = g.user["id"] if g.get("user") else None
    db().execute("INSERT INTO audit_log(user_id,action,entity,entity_id,detail) VALUES(?,?,?,?,?)",
                 (uid, action, entity, None if entity_id is None else str(entity_id), detail))


# ---------- passwords, tokens ----------
def hash_password(pw):
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${h.hex()}"


def verify_password(pw, stored):
    try:
        _, salt, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(calc.hex(), h)
    except Exception:
        return False


_DUMMY = hash_password("dummy-password-for-timing")


def check_password_policy(pw):
    if len(pw) < 10 or not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
        err(422, "validation_error", "Validation failed", {"password": "At least 10 characters with letters and digits"})


def issue_token(user):
    t = int(time.time())
    exp = t + current_app.config["TOKEN_TTL"]
    claims = {"sub": str(user["id"]), "role": user["role"], "jti": uuid.uuid4().hex, "iat": t, "exp": exp}
    return jwt.encode(claims, current_app.config["SECRET_KEY"], algorithm="HS256"), exp


def load_user():
    hdr = request.headers.get("Authorization", "")
    if not hdr.startswith("Bearer "):
        err(401, "unauthorized", "Authentication required")
    try:
        p = jwt.decode(hdr[7:], current_app.config["SECRET_KEY"], algorithms=["HS256"])
    except jwt.PyJWTError:
        err(401, "unauthorized", "Invalid or expired token")
    if db().execute("SELECT 1 FROM revoked_tokens WHERE jti=?", (p["jti"],)).fetchone():
        err(401, "unauthorized", "Token has been revoked")
    u = db().execute("SELECT id,email,name,role,active FROM users WHERE id=?", (int(p["sub"]),)).fetchone()
    if not u or not u["active"]:
        err(401, "unauthorized", "Account unavailable")
    g.user, g.token = dict(u), p
    return g.user


def require(*roles):
    """Authenticate; if roles given, also require one of them (checked against the DB, not the token)."""
    def deco(fn):
        @functools.wraps(fn)
        def w(*a, **k):
            u = load_user()
            if roles and u["role"] not in roles:
                err(403, "forbidden", "You do not have permission for this action")
            return fn(*a, **k)
        return w
    return deco


_hits = {}


def rate_limit(bucket, limit, window=60):
    if not current_app.config["RATELIMIT_ENABLED"]:
        return
    t, key = time.time(), (bucket, request.remote_addr)
    q = [x for x in _hits.get(key, []) if t - x < window]
    if len(q) >= limit:
        err(429, "rate_limited", "Too many requests, please try again later")
    q.append(t)
    _hits[key] = q


# ---------- validation ----------
def validate(fields, data, partial=False):
    if not isinstance(data, dict):
        err(400, "bad_request", "A JSON object body is required")
    clean, errors = {}, {}
    for name, spec in fields.items():
        if name not in data:
            if spec.get("required") and not partial:
                errors[name] = "Required"
            continue
        v, t = data[name], spec.get("type", "str")
        if v is None or (isinstance(v, str) and v.strip() == ""):
            if spec.get("required"):
                errors[name] = "Required"
            else:
                clean[name] = None
            continue
        try:
            if t == "str":
                if not isinstance(v, str):
                    raise Bad("Must be text")
                if spec.get("strip", True):
                    v = v.strip()
                if len(v) > spec.get("max", 200):
                    raise Bad(f"At most {spec.get('max', 200)} characters")
                if "pattern" in spec and not re.fullmatch(spec["pattern"], v):
                    raise Bad(spec.get("pattern_msg", "Invalid format"))
            elif t in ("int", "float"):
                if isinstance(v, bool):
                    raise Bad("Must be a number")
                try:
                    f = float(v)
                except (TypeError, ValueError):
                    raise Bad("Must be a number")
                if f != f or f in (float("inf"), float("-inf")):
                    raise Bad("Must be a number")
                if t == "int":
                    if not f.is_integer():
                        raise Bad("Must be a whole number")
                    v = int(f)
                else:
                    v = f
                if "min" in spec and v < spec["min"]:
                    raise Bad(f"Must be at least {spec['min']}")
                if "max" in spec and v > spec["max"]:
                    raise Bad(f"Must be at most {spec['max']}")
            elif t == "enum":
                if v not in spec["choices"]:
                    raise Bad("Must be one of: " + ", ".join(spec["choices"]))
            elif t == "date":
                if not isinstance(v, str):
                    raise Bad("Invalid date")
                datetime.strptime(v, "%Y-%m-%d")
            elif t == "datetime":
                if not isinstance(v, str):
                    raise Bad("Invalid date and time")
                v = datetime.fromisoformat(v).strftime("%Y-%m-%dT%H:%M")
            elif t == "bool":
                if not isinstance(v, bool):
                    raise Bad("Must be true or false")
                v = int(v)
            if "fk" in spec and not db().execute(f"SELECT 1 FROM {spec['fk']} WHERE id=?", (v,)).fetchone():
                raise Bad("Referenced record does not exist")
        except Bad as e:
            errors[name] = str(e)
        except (ValueError, TypeError):
            errors[name] = "Invalid value"
        else:
            clean[name] = v
    if errors:
        err(422, "validation_error", "Validation failed", errors)
    return clean


def int_arg(name, default, lo, hi):
    raw = request.args.get(name)
    if raw in (None, ""):
        return default
    try:
        return max(lo, min(hi, int(raw)))
    except ValueError:
        err(400, "bad_request", f"{name} must be an integer")


def page_meta(page, per, total):
    return {"page": page, "per_page": per, "total": total, "pages": max(1, -(-total // per))}


# ---------- generic CRUD resource ----------
class Resource:
    def __init__(self, name, table, fields, *, read=None, write=None, delete=None,
                 allow=("list", "get", "create", "update", "delete"), search=(), sortable=None,
                 filters=(), select="t.*", joins="", default_sort="t.id DESC",
                 hook_create=None, hook_update=None, hook_delete=None, post_create=None,
                 scope=None, audit_reads=False):
        for k, v in list(locals().items()):
            if k != "self":
                setattr(self, k, v)
        self.sortable = sortable or {}

    def register(self, app):
        base, n = f"/api/{self.name}", self.name

        def add(rule, ep, fn, methods, roles):
            app.add_url_rule(rule, f"{n}_{ep}", require(*(roles or ()))(fn), methods=methods)

        if "list" in self.allow:
            add(base, "list", self.list, ["GET"], self.read)
        if "create" in self.allow:
            add(base, "create", self.create, ["POST"], self.write)
        if "get" in self.allow:
            add(base + "/<int:rid>", "get", self.get, ["GET"], self.read)
        if "update" in self.allow:
            add(base + "/<int:rid>", "update", self.update, ["PUT", "PATCH"], self.write)
        if "delete" in self.allow:
            add(base + "/<int:rid>", "delete", self.remove, ["DELETE"], self.delete)

    def _scope(self):
        r = self.scope(g.user) if self.scope else None
        return ([r[0]], list(r[1])) if r else ([], [])

    def _one(self, rid, scoped=True):
        w, a = self._scope() if scoped else ([], [])
        sql = f"SELECT {self.select} FROM {self.table} t {self.joins} WHERE " + " AND ".join(["t.id=?"] + w)
        row = db().execute(sql, [rid] + a).fetchone()
        if not row:
            err(404, "not_found", "Record not found")
        return dict(row)

    def list(self):
        where, args = self._scope()
        q = request.args.get("q", "").strip()[:100]
        if q and self.search:
            where.append("(" + " OR ".join(f"{c} LIKE ? ESCAPE '\\'" for c in self.search) + ")")
            like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            args += [like] * len(self.search)
        for f in self.filters:
            v = request.args.get(f)
            if v not in (None, ""):
                where.append(f"t.{f} = ?")
                args.append(v)
        order = self.default_sort
        col = self.sortable.get(request.args.get("sort", ""))
        if col:
            order = f"{col} {'ASC' if request.args.get('order') == 'asc' else 'DESC'}, t.id DESC"
        page, per = int_arg("page", 1, 1, 10**6), int_arg("per_page", 10, 1, 100)
        w = (" WHERE " + " AND ".join(where)) if where else ""
        total = db().execute(f"SELECT COUNT(*) FROM {self.table} t {self.joins}{w}", args).fetchone()[0]
        rows = db().execute(f"SELECT {self.select} FROM {self.table} t {self.joins}{w} ORDER BY {order} LIMIT ? OFFSET ?",
                            args + [per, (page - 1) * per]).fetchall()
        return jsonify(data=[dict(r) for r in rows], meta=page_meta(page, per, total))

    def get(self, rid):
        row = self._one(rid)
        if self.audit_reads:
            with tx():
                audit("read", self.name, rid)
        return jsonify(data=row)

    def create(self):
        clean = validate(self.fields, request.get_json(silent=True))
        if self.hook_create:
            clean = self.hook_create(clean) or clean
        cols = list(clean)
        extra = {}
        with tx() as c:
            rid = c.execute(f"INSERT INTO {self.table}({','.join(cols)}) VALUES({','.join('?' * len(cols))})",
                            [clean[k] for k in cols]).lastrowid
            audit("create", self.name, rid)
            if self.post_create:
                extra = self.post_create(c, rid, clean) or {}
        return jsonify(data={**self._one(rid, scoped=False), **extra}), 201

    def update(self, rid):
        existing = self._one(rid)
        clean = validate(self.fields, request.get_json(silent=True), partial=True)
        if self.hook_update:
            clean = self.hook_update(clean, existing) or clean
        if clean:
            with tx() as c:
                c.execute(f"UPDATE {self.table} SET {','.join(k + '=?' for k in clean)} WHERE id=?", [*clean.values(), rid])
                audit("update", self.name, rid, ",".join(clean))
        return jsonify(data=self._one(rid, scoped=False))

    def remove(self, rid):
        existing = self._one(rid)
        if self.hook_delete:
            self.hook_delete(existing)
        with tx() as c:
            c.execute(f"DELETE FROM {self.table} WHERE id=?", (rid,))
            audit("delete", self.name, rid)
        return jsonify(data={"deleted": rid})


# ---------- app factory ----------
def make_app(root, *, roles, default_role, directory_roles=None, audit_roles=("admin",), on_register=None, config=None):
    root = Path(root)
    app = Flask(__name__, static_folder=None)
    env = os.environ
    app.config.update(
        APP_ENV=env.get("APP_ENV", "development"),
        SECRET_KEY=env.get("SECRET_KEY"),
        DATABASE_PATH=env.get("DATABASE_PATH", str(root / "data" / "app.db")),
        TOKEN_TTL=int(env.get("TOKEN_TTL_SECONDS", 1800)),
        CORS_ORIGINS=[o.strip() for o in env.get("CORS_ORIGINS", "").split(",") if o.strip()],
        RATELIMIT_ENABLED=env.get("RATELIMIT_ENABLED", "1") == "1",
        RATELIMIT_LOGIN=int(env.get("RATELIMIT_LOGIN", 10)),
        MAX_CONTENT_LENGTH=1 << 20,
    )
    app.config.update(config or {})
    if not app.config["SECRET_KEY"]:
        if app.config["APP_ENV"] == "production":
            raise RuntimeError("SECRET_KEY must be set in production")
        app.config["SECRET_KEY"] = secrets.token_hex(32)
    elif app.config["APP_ENV"] == "production" and len(app.config["SECRET_KEY"]) < 32:
        raise RuntimeError("SECRET_KEY must be at least 32 characters in production")
    if not app.testing:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    _hits.clear()
    migrate(app.config["DATABASE_PATH"], root / "migrations")

    @app.teardown_appcontext
    def close_db(_):
        c = g.pop("db", None)
        if c is not None:
            c.close()

    @app.errorhandler(ApiError)
    def on_api_error(e):
        body = {"code": e.code, "message": e.message}
        if e.details:
            body["details"] = e.details
        return jsonify(error=body), e.status

    @app.errorhandler(sqlite3.IntegrityError)
    def on_integrity(_):
        return jsonify(error={"code": "conflict", "message": "Operation conflicts with existing data (duplicate or referenced record)"}), 409

    @app.errorhandler(HTTPException)
    def on_http(e):
        return jsonify(error={"code": (e.name or "error").lower().replace(" ", "_"), "message": e.description}), e.code

    @app.errorhandler(Exception)
    def on_exc(e):
        app.logger.exception("Unhandled error")
        return jsonify(error={"code": "server_error", "message": "Internal server error"}), 500

    @app.after_request
    def headers(resp):
        resp.headers.update({
            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        })
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        if app.config["APP_ENV"] == "production":
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        origin = request.headers.get("Origin")
        if origin and origin in app.config["CORS_ORIGINS"]:
            resp.headers.update({"Access-Control-Allow-Origin": origin, "Vary": "Origin",
                                 "Access-Control-Allow-Headers": "Authorization, Content-Type, X-Agent-Key",
                                 "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS"})
        app.logger.info("%s %s -> %s", request.method, request.path, resp.status_code)
        return resp

    front = root / "frontend"

    @app.get("/api/health")
    def health():
        db().execute("SELECT 1").fetchone()
        return jsonify(status="ok")

    @app.post("/api/auth/register")
    def register():
        rate_limit("register", app.config["RATELIMIT_LOGIN"])
        d = validate({"email": {"required": True, "max": 254, "pattern": EMAIL_RE, "pattern_msg": "Invalid email address"},
                      "name": {"required": True, "max": 100},
                      "password": {"required": True, "max": 128, "strip": False}}, request.get_json(silent=True))
        check_password_policy(d["password"])
        try:
            with tx() as c:
                uid = c.execute("INSERT INTO users(email,name,password_hash,role) VALUES(?,?,?,?)",
                                (d["email"].lower(), d["name"], hash_password(d["password"]), default_role)).lastrowid
                if on_register:
                    on_register(c, uid, d)
                audit("register", "users", uid)
        except sqlite3.IntegrityError:
            err(409, "conflict", "An account with this email already exists")
        return jsonify(data={"id": uid, "email": d["email"].lower(), "name": d["name"], "role": default_role}), 201

    @app.post("/api/auth/login")
    def login():
        rate_limit("login", app.config["RATELIMIT_LOGIN"])
        d = request.get_json(silent=True)
        if not isinstance(d, dict) or not isinstance(d.get("email"), str) or not isinstance(d.get("password"), str):
            err(400, "bad_request", "Email and password are required")
        u = db().execute("SELECT * FROM users WHERE email=?", (d["email"].strip().lower(),)).fetchone()
        ok = verify_password(d["password"], u["password_hash"] if u else _DUMMY)
        if not (u and ok and u["active"]):
            err(401, "invalid_credentials", "Invalid email or password")
        token, exp = issue_token(u)
        return jsonify(data={"token": token, "expires_at": exp,
                             "user": {"id": u["id"], "email": u["email"], "name": u["name"], "role": u["role"]}})

    @app.post("/api/auth/logout")
    @require()
    def logout():
        with tx() as c:
            c.execute("INSERT OR IGNORE INTO revoked_tokens(jti,expires_at) VALUES(?,?)", (g.token["jti"], g.token["exp"]))
            c.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (int(time.time()),))
        return jsonify(data={"logged_out": True})

    @app.get("/api/auth/me")
    @require()
    def me():
        return jsonify(data=g.user)

    @app.get("/api/directory")
    @require()
    def directory():
        rs = list(directory_roles or roles)
        rows = db().execute(f"SELECT id,name,role FROM users WHERE active=1 AND role IN ({','.join('?' * len(rs))}) ORDER BY name", rs).fetchall()
        return jsonify(data=[dict(r) for r in rows])

    def protect_self(clean, existing):
        if existing["id"] == g.user["id"] and (clean.get("active") == 0 or ("role" in clean and clean["role"] != existing["role"])):
            err(409, "conflict", "You cannot deactivate or change the role of your own account")

    Resource("users", "users", {"name": {"max": 100}, "role": {"type": "enum", "choices": list(roles)}, "active": {"type": "bool"}},
             read=("admin",), write=("admin",), allow=("list", "get", "update"), search=("t.name", "t.email"),
             filters=("role",), select="t.id,t.email,t.name,t.role,t.active,t.created_at", hook_update=protect_self,
             sortable={"name": "t.name", "created_at": "t.id"}).register(app)

    @app.post("/api/users/<int:uid>/reset-password")
    @require("admin")
    def reset_password(uid):
        d = validate({"password": {"required": True, "max": 128, "strip": False}}, request.get_json(silent=True))
        check_password_policy(d["password"])
        with tx() as c:
            if not c.execute("SELECT 1 FROM users WHERE id=?", (uid,)).fetchone():
                err(404, "not_found", "Record not found")
            c.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(d["password"]), uid))
            audit("reset_password", "users", uid)
        return jsonify(data={"reset": True})

    Resource("audit", "audit_log", {}, read=audit_roles, allow=("list",), search=("t.action", "t.entity", "u.email"),
             filters=("entity", "action"), select="t.id,t.action,t.entity,t.entity_id,t.detail,t.created_at,u.email AS user_email",
             joins="LEFT JOIN users u ON u.id=t.user_id").register(app)

    @app.get("/")
    def index():
        return send_from_directory(front, "index.html")

    @app.get("/<path:p>")
    def assets(p):
        if p.startswith("api/"):
            err(404, "not_found", "Endpoint not found")
        return send_from_directory(front, p)

    return app


def seed_users(conn, rows):
    """rows: (email, name, role). Skips if users already exist."""
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
        return False
    for email, name, role in rows:
        conn.execute("INSERT INTO users(email,name,password_hash,role) VALUES(?,?,?,?)", (email, name, hash_password(DEMO_PASSWORD), role))
    return True
