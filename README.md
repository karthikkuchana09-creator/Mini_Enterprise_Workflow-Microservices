# Mini Enterprise Workflow (ECWF) — Microservices Backend

Enterprise Collaboration and Workflow Tool backend, built as three
microservices behind a shared MySQL server, with Docker Compose for the full
stack and real email (SMTP/Gmail) delivery of OTP codes.

## Architecture

```
                          ┌─────────────────────┐
                          │   MySQL (:3308)     │
                          │  ecwf_auth_db       │
                          │  ecwf_tenant_db     │
                          └──────┬──────┬───────┘
                                 │      │
   ┌──────────────────┐  ┌───────▼──┐  ┌▼───────────────────┐
   │  auth-service    │  │ tenant-  │  │  notification-     │
   │  (:8001)         │──│ service  │  │  service (:8004)   │
   │  /auth, /users,  │  │ (:8003)  │  │  SMTP email        │
   │  /internal/user* │  │ /tenants │  │  /internal/emails* │
   └─────────┬────────┘  └──────────┘  └────────────────────┘
             └── internal HTTP (shared key header) ─────►┘
```

- **authentication-service** (:8001) — registration (individual + organization),
  OTP email verification, login, refresh-token rotation, logout, password
  recovery, user profiles, internal user API.
- **tenant-service** (:8003) — organizations, tenant admins, profile completion,
  invitations, dashboard.
- **notification-service** (:8004) — SMTP email delivery (OTP, welcome,
  invite, password reset, etc.).
- **shared/** — cross-service contracts: internal HTTP client, API-key auth,
  correlation middleware.
- Internal service-to-service calls are protected by the `X-Internal-API-Key`
  header (shared secret).

## Quick start

From `backend/`:

```powershell
# Full stack (MySQL + 3 services)
cp .env.example .env   # set your SMTP credentials & internal API key
docker compose up -d --build
```

| Service | URL |
| --- | --- |
| auth (OpenAPI docs) | http://localhost:8001/docs |
| tenant (OpenAPI docs) | http://localhost:8003/docs |
| notification | http://localhost:8004/docs |
| MySQL | localhost:3308 |

## Running tests (monolith suite)

```powershell
$env:PYTHONPATH = ".;services/authentication-service;services/tenant-service;services/notification-service;shared"
python -m pytest --no-cov -p no:cacheprovider -q services/authentication-service/app/tests
```

## Key auth flows

1. `POST /auth/register` → OTP emailed → `POST /auth/verify-otp` (cookie-bound).
2. `POST /auth/login` → `access_token` + `refresh_token` (rotation via
   `/auth/refresh`, revoke via `/auth/logout`).
3. `POST /auth/forgot-password` → OTP → `/auth/reset-password`.
4. Organization setup: register org → verify → complete tenant profile →
   dashboard.

Secrets (SMTP app password, internal API key) live only in `backend/.env`, which
is git-ignored; never commit `.env`.