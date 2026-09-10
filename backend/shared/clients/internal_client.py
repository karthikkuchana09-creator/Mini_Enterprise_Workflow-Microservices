"""Internal HTTP client base for service-to-service calls.

Every client performs synchronous requests (FastAPI sync endpoints + sync
service layer) while the transport itself is HTTPX's ``AsyncClient`` - the
shared ``shared.core.internal_http`` helpers already shape the async behavior.
The async call is driven to completion with ``asyncio.run``; in the FastAPI
threadpool and in pytest sync tests no event loop is running in the calling
thread, so this never collides with a live loop.

Remote error statuses are mapped onto the ECWF exception classes so the
service layer keeps the same ``except NotFoundError: ...`` semantics it had in
monolith mode.
"""
import asyncio
import logging
from types import SimpleNamespace
from typing import Any, Optional

import httpx

from app.core.exceptions import (
    BadRequestError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    UnauthorizedError,
    ValidationError_,
)
from shared.constants.headers import INTERNAL_API_KEY_HEADER

logger = logging.getLogger("ecwf.internal-client")

_STATUS_MAP = {
    400: BadRequestError,
    401: UnauthorizedError,
    403: ForbiddenError,
    404: NotFoundError,
    409: ConflictError,
    422: ValidationError_,
}


class InternalClientError(Exception):
    """Transport-level failure (timeout / unreachable / unknown status)."""

    def __init__(self, status_code: int, service: str, detail: Any = None):
        self.status_code = status_code
        self.service = service
        self.detail = detail
        super().__init__(f"{service} HTTP {status_code}: {detail}")


class InternalApiClient:
    def __init__(self, base_url: str, api_key: str, service_label: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.service_label = service_label
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {
            INTERNAL_API_KEY_HEADER: self.api_key,
            "Content-Type": "application/json",
        }

    def _request(self, method: str, path: str, json: Optional[dict] = None) -> httpx.Response:
        async def _call() -> httpx.Response:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout, connect=5.0)
            ) as client:
                return await client.request(
                    method, f"{self.base_url}{path}", json=json, headers=self._headers()
                )

        try:
            return asyncio.run(_call())
        except httpx.TimeoutException as exc:
            raise InternalClientError(504, self.service_label, "request timed out") from exc
        except httpx.RequestError as exc:
            raise InternalClientError(503, self.service_label, "service unavailable") from exc

    def _map_error(self, response: httpx.Response) -> Exception:
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        detail = (
            payload.get("message")
            or payload.get("detail")
            or response.text
            or "request failed"
        )
        exc_cls = _STATUS_MAP.get(response.status_code, InternalClientError)
        if exc_cls is InternalClientError:
            return InternalClientError(response.status_code, self.service_label, detail)
        return exc_cls(detail)

    def _json(self, method: str, path: str, json_body: Optional[dict] = None) -> Any:
        """Perform a request and return the JSON body or raise a mapped error."""
        response = self._request(method, path, json=json_body)
        if response.status_code < 300:
            if response.status_code == 204 or not response.content:
                return None
            return response.json()
        raise self._map_error(response)

    def _data(self, method: str, path: str, json_body: Optional[dict] = None) -> SimpleNamespace:
        """Like ``_json`` but wraps the payload as an attribute-accessible object."""
        data = self._json(method, path, json_body=json_body)
        if data is None:
            return SimpleNamespace()
        return _to_namespace(data)


def _to_namespace(payload: Any) -> Any:
    if isinstance(payload, dict):
        return SimpleNamespace(**{k: _to_namespace(v) for k, v in payload.items()})
    if isinstance(payload, list):
        return [_to_namespace(item) for item in payload]
    return payload