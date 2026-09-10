# ECWF Backend

Modular service-shaped architecture for the Enterprise Collaboration and Workflow
Tool. The code is organized as microservice-style packages (mirroring the
`ECWF-Microservices` reference) while today running as a single composed,
testable unit — the "modular monolith" stage.

## Layout

```
backend/
├── services/
│   ├── authentication-service/       # Identity, registration, OTP, users
│   │   ├── app/                      #   importable package `app` (FastAPI host)
│   │   │   ├── api/                  #   auth_routes, user_routes, exception_handlers
│   │   │   ├── core/                 #   config, constants, emails, exceptions, security
│   │   │   ├── db/                   #   base, session
│   │   │   ├── dependencies/         #   auth_deps
│   │   │   ├── middleware/           #   cors
│   │   │   ├── models/               #   auth, user (+ re-imports tenant models for metadata)
│   │   │   ├── repositories/         #   auth_repo, user_repo
│   │   │   ├── schemas/              #   auth, user
│   │   │   ├── services/             #   auth_service, otp_service, user_service
│   │   │   └── tests/                #   full integration suite (120 tests)
│   │   ├── alembic/                  #   migrations (head: fb1f8090a5ab)
│   │   ├── alembic.ini               #   migrations config
│   │   ├── Dockerfile / entrypoint.sh
│   │   ├── requirements.txt / .env.example
│   ├── tenant-service/               # Organization + tenant management
│   │   └── tenant/                   #   importable package `tenant`
│   │       ├── api/v1/endpoints/tenant.py
│   │       ├── models/ repositories/ schemas/ services/
│   │       └── Dockerfile / requirements.txt / ...
│   └── notification-service/         # Email notifications
│       └── notification/             #   importable package `notification`
│           ├── services/notification_service.py
│           └── Dockerfile / requirements.txt / ...
├── shared/                           # Cross-service contracts (ECWF-Microservices style)
│   ├── constants/ headers.py, service_names.py
│   ├── core/ internal_http.py
│   ├── database/ connection.py
│   ├── dependencies/ internal_auth.py
│   ├── middleware/ correlation_id.py
│   └── pyproject.toml / requirements.txt
├── infrastructure/mysql/init.sql     # shared MySQL: auth/tenant/notification DBs + users
├── docker-compose.yml                # compose mirror (services + mysql)
├── pytest.ini                        # pythonpath spans app, tenant, notification, shared
├── .env / .env.example
└── .gitignore
```

## Stage notes

- **Composed app:** `services/authentication-service/app/main.py` hosts the
  auth, user, and tenant API routers. The `tenant` and `notification` packages
  are imported as libraries (single process, one DB, no HTTP fan-out — an event
  bus/outbox has not been introduced).
- **Shared:** `shared/` provides the internal-service contracts (headers,
  `call_downstream`, `create_internal_auth`, correlation middleware) used when
  services are split out; not yet wired into the composed app.
- **Per-service folders** carry their own requirements, `.env.example`,
  Dockerfile, and entrypoint. The tenant/notification containers currently
  verify package import; they become fully-hosted services at the split stage.

## Running

All commands run from `backend/` (CWD matters: `.env`, `db` files live here).

```bash
# Tests (120)
python -m pytest

# Dev server (composed app) — PowerShell
$env:PYTHONPATH = "services\authentication-service;services\tenant-service;services\notification-service;shared"
uvicorn app.main:app --reload

# Migrations (auth-service alembic config)
alembic -c services/authentication-service/alembic.ini upgrade head

# MySQL + service images (optional, mirror of the target deployment)
docker compose up
```

`.env` at `backend/` configures the runtime (`DATABASE_URL=sqlite:///./ecwf_test.db`
in local/test).