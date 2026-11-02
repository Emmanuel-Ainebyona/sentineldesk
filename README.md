# SentinelDesk

> Security incident & vulnerability management platform

A web application for small security teams to track assets, vulnerabilities (with CVSS-derived severity and SLA deadlines) and incidents (with an enforced response workflow), backed by an audit trail.

**Problem solved:** Security teams often track incidents and vulnerabilities in spreadsheets: nothing is assigned, SLAs are missed silently and there is no audit trail.

## Features
- Incident lifecycle (new, triaged, contained, resolved, closed) with enforced transitions and per-incident event history
- Vulnerability register: CVSS score drives severity and SLA due date server-side; overdue detection
- Asset inventory linked to findings (assets with findings cannot be deleted)
- Role-based access: admin, analyst (read/write), auditor (read-only, default for new sign-ups)
- Immutable-style audit log of every change, readable by admin and auditor
- Dashboard with live aggregates; search, filter, sort and pagination on every table

## Roles
admin: everything incl. deletes and user management. analyst: create/edit assets, vulnerabilities, incidents and advance workflow. auditor: read-only plus audit log.

## Technology stack
| Layer | Technology |
|---|---|
| Frontend | Vanilla JavaScript single-page app (no build step), responsive CSS, accessible dialogs/forms |
| Backend | Python 3.12, Flask 3, PyJWT, scrypt password hashing (standard library) |
| Database | SQLite (WAL-safe, foreign keys on) with versioned SQL migrations |
| Ops | Docker, Docker Compose, GitHub Actions CI, gunicorn |

> **Design note:** the stack was chosen so the project runs from a clean checkout with two dependencies and no build step. The data layer is plain SQL with explicit transactions, so porting to PostgreSQL is mostly a matter of dialect changes in `migrations/` and `app/core.py` (see *Limitations*).

## Architecture
```
Browser (frontend/*.js) --JSON/HTTPS--> Flask app (app/)
   config.js defines screens           core.py: auth, RBAC, validation, generic CRUD Resource, audit, security headers
   ui.js renders tables/forms          __init__.py: this project's resources, business rules, endpoints
                                       SQLite via migrations/*.sql (000_base = users, audit; 001 = domain schema)
```

## Quick start
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # optional in development (a random SECRET_KEY is generated per process)
python manage.py migrate        # applies migrations (also applied automatically on startup)
python manage.py seed           # loads clearly-labelled demo data
python manage.py run            # http://127.0.0.1:8000
```
Demo accounts (admin@demo.test, analyst@demo.test, auditor@demo.test) all use the local-only password `Demo-Pass-2026!`. **Never use demo credentials or demo data in production.**

New users can also register on the sign-in screen. Password recovery by e-mail is not implemented (no mail service); admins reset passwords from the Users screen.

## Environment variables
See `.env.example`. Key ones: `APP_ENV` (`production` enforces `SECRET_KEY` of 32+ chars and adds HSTS), `SECRET_KEY`, `DATABASE_PATH`, `TOKEN_TTL_SECONDS`, `CORS_ORIGINS`, `RATELIMIT_ENABLED`, `RATELIMIT_LOGIN`.

## Database
Migrations live in `migrations/` and are applied in filename order, tracked in `schema_migrations`. Seed data: `python manage.py seed` (idempotent: skipped if users exist). Integrity is enforced by primary/foreign keys, CHECK constraints, unique and partial indexes.

## Testing
```bash
python -m unittest discover -s tests -t . -v     # backend unit + API integration + security tests
for f in frontend/*.js; do node --check "$f"; done  # frontend syntax check
python manage.py seed && python manage.py run &      # then:
python scripts/smoke.py http://127.0.0.1:8000        # live HTTP smoke test
```
**Result of the last run in the authoring environment:** Ran 34 tests in 9.771s OK  (34 tests; 34 PASS).
Full per-test results: see `docs/TEST_REPORT.md`.

**Not covered:** browser-level UI tests (the frontend was only syntax-checked, never exercised in a real browser), dependency vulnerability scanning (`pip-audit` runs in CI), Docker image build, and load/accessibility testing. Screenshots are not included because none could be captured honestly.

## API
See `docs/API.md` (generated from the running application's routes).

## Project structure
```
.env.example
.github/workflows/ci.yml
.gitignore
CONTRIBUTING.md
Dockerfile
SECURITY.md
app/__init__.py
app/core.py
app/seed.py
docker-compose.yml
docs/API.md
frontend/config.js
frontend/index.html
frontend/styles.css
frontend/ui.js
manage.py
migrations/000_base.sql
migrations/001_sentineldesk.sql
requirements-prod.txt
requirements.txt
scripts/smoke.py
tests/__init__.py
tests/base.py
tests/test_core.py
tests/test_domain.py
```

## Production build and deployment (Linux)
**Docker:** `cp .env.example .env`, set `SECRET_KEY`, then `docker compose up -d --build`. Data lives in the `appdata` volume.

**Without Docker (systemd + nginx):**
```bash
sudo useradd --system --home /srv/sentineldesk sentineldesk; sudo git clone <repo> /srv/sentineldesk; cd /srv/sentineldesk
sudo python3 -m venv .venv && sudo .venv/bin/pip install -r requirements-prod.txt
sudo -u sentineldesk cp .env.example .env     # set APP_ENV=production, SECRET_KEY, DATABASE_PATH=/var/lib/sentineldesk/app.db
```
`/etc/systemd/system/sentineldesk.service`:
```ini
[Service]
User=sentineldesk
WorkingDirectory=/srv/sentineldesk
EnvironmentFile=/srv/sentineldesk/.env
ExecStart=/srv/sentineldesk/.venv/bin/gunicorn --bind 127.0.0.1:8000 --workers 1 --threads 8 "app:create_app()"
Restart=always
[Install]
WantedBy=multi-user.target
```
nginx site: `location / { proxy_pass http://127.0.0.1:8000; proxy_set_header Host $host; proxy_set_header X-Forwarded-For $remote_addr; proxy_set_header X-Forwarded-Proto $scheme; }`, then `sudo certbot --nginx -d your.domain` for HTTPS.
Create the first real admin by seeding nothing in production: register a user, then promote it with `sqlite3 $DATABASE_PATH "UPDATE users SET role='admin' WHERE email='you@example.com'"`.

**Development vs production:** development uses a random per-process secret and the Flask dev server; production requires `SECRET_KEY`, runs under gunicorn behind HTTPS and must not load demo seed data.

## Backup and restore
```bash
sqlite3 "$DATABASE_PATH" ".backup '/backups/sentineldesk-$(date +%F).db'"   # safe while running
# restore: stop the service, then
cp /backups/sentineldesk-YYYY-MM-DD.db "$DATABASE_PATH" && sudo systemctl start sentineldesk
```

## Troubleshooting
| Symptom | Fix |
|---|---|
| `RuntimeError: SECRET_KEY must be set in production` | Set a 32+ character `SECRET_KEY` (see `.env.example`). |
| `Address already in use` | Another process uses the port: `PORT=8001 python manage.py run`. |
| `database is locked` | Only one process should write; run a single gunicorn worker. |
| Logged out after every restart in development | No `SECRET_KEY` set; add one to `.env`. |
| `ModuleNotFoundError: flask` | Activate the venv and `pip install -r requirements.txt`. |
| 429 responses | Rate limit hit; wait a minute or raise `RATELIMIT_LOGIN`. |

## Limitations (please read)
- Severity and SLA due dates are computed on the server; client-supplied values are ignored (tested).
- Incident status can only change through the transition endpoint, never through a generic update (tested).
- SQLite and an in-process rate limiter assume a single application process.
- No refresh tokens or MFA; see `SECURITY.md`.
- Tests ran against SQLite only; the PostgreSQL port has not been attempted.

## Suggested GitHub metadata
- **Description:** Security incident & vulnerability management platform (Flask + SQLite, RBAC, audit log, tests, Docker, CI)
- **Topics:** security incident-response vulnerability-management cvss flask sqlite rbac audit-log portfolio
- **Suggested commits:** feat: base auth, RBAC, audit log; feat: assets and vulnerabilities with CVSS/SLA rules; feat: incident workflow and event history; feat: dashboard and frontend; test: domain and security test suites; chore: docker, CI, docs

## License
No license has been selected. Add a `LICENSE` file of your choice (for example MIT) before publishing if you want others to reuse the code.
