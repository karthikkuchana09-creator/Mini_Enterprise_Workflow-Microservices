from typing import Optional

from fastapi import Cookie, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.constants import TokenType, UserRole, UserStatus
from app.core.exceptions import ForbiddenError, UnauthorizedError
from app.core.security import decode_token
from app.db.session import get_db
from app.services.user_service import UserService


bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    access_token: Optional[str] = Cookie(
        default=None, alias=settings.ACCESS_TOKEN_COOKIE_NAME
    ),
    db: Session = Depends(get_db),
):
    token = credentials.credentials if credentials else None
    if not token and access_token:
        token = access_token
    if not token:
        raise UnauthorizedError()

    try:
        payload = decode_token(token, TokenType.ACCESS)
    except ValueError:
        raise UnauthorizedError()

    user_id = payload.get("sub")
    if not user_id:
        raise UnauthorizedError()

    user = UserService(db).get_by_id(user_id)
    if not user:
        raise UnauthorizedError()
    if user.status != UserStatus.ACTIVE:
        raise ForbiddenError("Account is not active")
    return user


def require_role(*roles: UserRole):
    def dependency(user=Depends(get_current_user)):
        if user.role not in roles:
            raise ForbiddenError("Insufficient permissions")
        return user

    return dependency


def require_tenant(tenant_id: str, user=Depends(get_current_user)) -> str:
    if not user.tenant_id or user.tenant_id != tenant_id:
        raise ForbiddenError("User does not belong to this tenant")
    return tenant_id
