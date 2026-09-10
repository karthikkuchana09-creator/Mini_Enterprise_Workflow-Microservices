"""Tenant Service - standalone FastAPI application.

Runs as an independent microservice (uvicorn on port 8003) exposing:
- the public organization API (requires a valid access JWT, validated against
  auth-service over HTTP),
- the internal tenant API for service-to-service calls (auth-service).

Owns the ``tenants`` / ``tenant_admins`` / ``tenant_invitations`` tables in the
shared MySQL server.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.exception_handlers import register_exception_handlers
from tenant.api.v1.endpoints.internal import router as internal_router
from tenant.api.v1.endpoints.tenant import router as public_router
from tenant.core import tenant_settings
from tenant.database import Base, engine


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="ECWF Tenant Service",
    version="1.0.0",
    description=(
        "ECWF Tenant Service. Manages organizations, their admins, and "
        "invitations in the tenant database. Public endpoints require a valid "
        "access token (users are resolved through auth-service); internal "
        "endpoints require the `X-Internal-API-Key` header."
    ),
    lifespan=_lifespan,
    openapi_tags=[
        {
            "name": "tenants",
            "description": "Organization endpoints for authenticated tenant admins.",
        },
        {
            "name": "internal-tenants",
            "description": "Service-to-service tenant endpoints.",
        },
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=tenant_settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

register_exception_handlers(app)

app.include_router(public_router)
app.include_router(internal_router)


@app.get("/health")
def health_check():
    return {"status": "success", "service": "tenant-service"}