from typing import Any, Optional

import httpx
from fastapi import HTTPException, status

from shared.constants.headers import INTERNAL_API_KEY_HEADER


def internal_headers(api_key: str) -> dict[str, str]:
    """Build headers used for secured service-to-service requests."""
    return {
        INTERNAL_API_KEY_HEADER: api_key,
        "Content-Type": "application/json",
    }


def http_timeout(service_timeout: float) -> httpx.Timeout:
    """Timeout applied to every downstream microservice request."""
    return httpx.Timeout(timeout=service_timeout, connect=5.0)


def response_detail(response: httpx.Response) -> Any:
    """Read an error response safely, whether it contains JSON or text."""
    try:
        return response.json()
    except ValueError:
        return response.text


async def call_downstream(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    service_label: str,
    data: Optional[dict] = None,
    *,
    api_key: str,
    service_timeout: float = 10.0,
) -> httpx.Response:
    """Call another microservice over HTTP and map transport failures.

    Timeouts become 504 Gateway Timeout, unreachable services become 503
    Service Unavailable. HTTP status handling stays at the call site.
    """
    headers = internal_headers(api_key)
    try:
        if method.upper() == "GET":
            response = await client.get(url, headers=headers)
        elif method.upper() == "DELETE":
            response = await client.delete(url, headers=headers)
        else:
            response = await client.request(method, url, json=data, headers=headers)
    except httpx.TimeoutException as exc:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=f"{service_label} request timed out",
        ) from exc
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"{service_label} is unavailable",
        ) from exc

    return response


def bad_gateway(service_label: str, expected: int, response: httpx.Response) -> HTTPException:
    """Build a 502 response that includes the downstream service failure."""
    return HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail={
            "message": f"{service_label} failed",
            "expected_status": expected,
            "service_status": response.status_code,
            "service_response": response_detail(response),
        },
    )