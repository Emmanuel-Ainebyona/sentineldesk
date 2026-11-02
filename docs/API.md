# API reference

Base path `/api`. Responses: `{"data": ...}` (+ `"meta": {page, per_page, total, pages}` for lists) or `{"error": {"code", "message", "details"?}}`.
Authenticate with `Authorization: Bearer <token>` from `POST /api/auth/login`. Public endpoints: `GET /api/health`, `POST /api/auth/register`, `POST /api/auth/login`.
List endpoints accept `q`, `page`, `per_page` (max 100), `sort`, `order=asc|desc` and resource-specific filters.

## Endpoints (generated from the running app)

| Path | Methods |
|---|---|
| `/api/assets` | GET |
| `/api/assets` | POST |
| `/api/assets/Falserid>` | DELETE |
| `/api/assets/Falserid>` | GET |
| `/api/assets/Falserid>` | PATCH, PUT |
| `/api/audit` | GET |
| `/api/auth/login` | POST |
| `/api/auth/logout` | POST |
| `/api/auth/me` | GET |
| `/api/auth/register` | POST |
| `/api/directory` | GET |
| `/api/health` | GET |
| `/api/incidents` | GET |
| `/api/incidents` | POST |
| `/api/incidents/Falseiid>/events` | GET |
| `/api/incidents/Falseiid>/transition` | POST |
| `/api/incidents/Falserid>` | DELETE |
| `/api/incidents/Falserid>` | GET |
| `/api/incidents/Falserid>` | PATCH, PUT |
| `/api/stats` | GET |
| `/api/users` | GET |
| `/api/users/Falserid>` | GET |
| `/api/users/Falserid>` | PATCH, PUT |
| `/api/users/Falseuid>/reset-password` | POST |
| `/api/vulnerabilities` | GET |
| `/api/vulnerabilities` | POST |
| `/api/vulnerabilities/Falserid>` | DELETE |
| `/api/vulnerabilities/Falserid>` | GET |
| `/api/vulnerabilities/Falserid>` | PATCH, PUT |

## Example

```bash
TOKEN=$(curl -s localhost:8000/api/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"admin@demo.test","password":"Demo-Pass-2026!"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["token"])')
curl -s localhost:8000/api/stats -H "Authorization: Bearer $TOKEN"
```
