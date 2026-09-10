"""HTTPX client for the auth-service internal user API.

Mirrors the in-process ``UserService`` interface used by tenant-service
(microservices mode). ``get_user_by_email`` collapses a 404 into ``None`` so
"does this email already exist?" checks behave like the local service.
"""
from typing import Optional

from app.core.exceptions import NotFoundError
from shared.clients.internal_client import InternalApiClient


class AuthClient(InternalApiClient):
    def __init__(self, base_url: str, api_key: str, timeout: float = 10.0):
        super().__init__(base_url, api_key, "auth-service", timeout)

    def get_user_by_email(self, email: str):
        try:
            return self._data("GET", f"/internal/users/by-email/{email}")
        except NotFoundError:
            return None

    def get_user_by_id(self, user_id: str):
        return self._data("GET", f"/internal/users/{user_id}")

    def create_user(
        self,
        email: str,
        full_name: str,
        user_type,
        role,
        status=None,
        tenant_id: Optional[str] = None,
    ):
        payload = {
            "email": email,
            "full_name": full_name,
            "user_type": _enum_value(user_type),
            "role": _enum_value(role),
            "status": _enum_value(status) if status is not None else "pending",
            "tenant_id": tenant_id,
        }
        return self._data("POST", "/internal/users", json_body=payload)

    def dashboard_counts(self, tenant_id: str) -> dict:
        return self._json("GET", f"/internal/users/dashboard-counts?tenant_id={tenant_id}")


def _enum_value(value) -> str:
    return value.value if hasattr(value, "value") else value