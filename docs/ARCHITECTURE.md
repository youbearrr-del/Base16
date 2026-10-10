# Architecture

```text
Monitoring web (localhost:4173) ──cookie session──> Versioned API (localhost:8788/api/v1)
                                                        │
APK/EXE client ── X-Application-Key ───────────────────┤
                                                        ▼
                                               SQLite (local development)
```

The current local implementation uses SQLite because it runs without installing a database service. It has a repository boundary in `backend/server.py`; production should replace the connection factory with PostgreSQL and use proper migrations. Clients never access the database directly.

Current entities: `users` (administrator identities), `applications`, `devices`, `accounts` (application-scoped records), `configurations`, `activity_logs`, and `revoked_tokens`. Passwords use PBKDF2-SHA256. API application secrets are only returned when created or regenerated; the database stores a hash.

Web session tokens are HMAC-signed and sent in `HttpOnly` cookies. A production deployment must use HTTPS, set the `Secure` cookie flag, restrict CORS to the actual frontend origin, rotate `TOKEN_SECRET`, and run behind a production ASGI/WSGI service or equivalent.
