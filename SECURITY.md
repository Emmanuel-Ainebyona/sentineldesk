# Security policy

## Reporting a vulnerability
Please open a private security advisory on GitHub (Security > Advisories) instead of a public issue. Include steps to reproduce and the affected version.

## Controls implemented
- Passwords hashed with scrypt (per-user random salt); password policy enforced server-side.
- JWT access tokens (HS256, default 30 min) with server-side revocation on logout; role and active status are re-read from the database on every request, so role changes and deactivation apply immediately.
- Role-based access control on every protected endpoint; secrets only via environment variables (production refuses to start without a strong `SECRET_KEY`).
- Parameterised SQL everywhere; sort/filter columns are whitelisted. React-free frontend renders data with `textContent`, plus a strict Content-Security-Policy.
- Rate limiting on login and registration; strict CORS allow-list; security headers; JSON errors that do not leak internals.

## Known limitations
- No refresh tokens, MFA or e-mail based password recovery (admins can reset passwords). Existing tokens remain valid until expiry after a password reset.
- In-process rate limiter: suitable for a single worker; use a reverse-proxy or shared store when scaling out.
- SQLite is used for portability; use a managed database for multi-node deployments.
- Bearer tokens are kept in `sessionStorage`; an XSS flaw would expose them, hence the CSP and `textContent` rendering.
