from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from shared.constants.headers import INTERNAL_API_KEY_HEADER


def create_internal_auth(api_key_setting: str):
    """Return a verify function bound to the given API key value."""
    header = APIKeyHeader(name=INTERNAL_API_KEY_HEADER, auto_error=False)

    def verify(api_key: str = Security(header)) -> str:
        if not api_key or api_key != api_key_setting:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid internal API key",
            )
        return api_key

    return verify