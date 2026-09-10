"""Authentication dependencies for tenant-service endpoints.

- ``monolith`` mode: reuse the auth-service in-process ``get_current_user`` /
  ``require_role`` / ``require_tenant`` (reads users from the shared database).
- ``microservices`` mode: validate the access JWT locally, then fetch the user
  record from auth-service over HTTP (the ``users`` table lives in the
  auth-service database).
"""
from typing import Optional

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from tenant.core import tenant_settings


if tenant_settings.SERVICE_MODE == "microservices":
    from app.core.constants import TokenType, UserRole, UserStatus
    from app.core.exceptions import ForbiddenError, UnauthorizedError
    from app.core.security import decode_token

    from shared.clients.auth_client import AuthClient

    _client = AuthClient(
        base_url=tenant_settings.AUTH_SERVICE_URL,
        api_key=tenant_settings.INTERNAL_API_KEY,
    )

    _bearer_scheme = HTTPBearer(auto_error=False)

    def get_current_user(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    ):
        token = credentials.credentials if credentials else None
        if not token:
            raise UnauthorizedError()
        try:
            payload = decode_token(token, TokenType.ACCESS)
        except ValueError:
            raise UnauthorizedError()

        user_id = payload.get("sub")
        if not user_id:
            raise UnauthorizedError()

        user = _client.get_user_by_id(user_id)
        if not user:
            raise UnauthorizedError()
        if user.status != UserStatus.ACTIVE.value:
            raise ForbiddenError("Account is not active")
        return user

    def require_role(*roles: UserRole):
        def dependency(user: object = Depends(get_current_user)):
            allowed = {r.value for r in roles}
            if user.role not in allowed:
                raise ForbiddenError("Insufficient permissions")
            return user

        return dependency

    def require_tenant(tenant_id: str, user: object = Depends(get_current_user)) -> str:
        if not user.tenant_id or user.tenant_id != tenant_id:
            raise ForbiddenError("User does not belong to this tenant")
        return tenant_id

else:
    from app.dependencies.auth_deps import (  # noqa: F401
        get_current_user,
        require_role,
        require_tenant,
    )