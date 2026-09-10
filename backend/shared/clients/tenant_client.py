"""HTTPX client for the tenant-service internal API.

Mirrors the in-process ``TenantService`` interface used by auth-service. Remote
404/409/422 responses raise the matching ECWF exception.
"""
from shared.clients.internal_client import InternalApiClient


class TenantClient(InternalApiClient):
    def __init__(self, base_url: str, api_key: str, timeout: float = 10.0):
        super().__init__(base_url, api_key, "tenant-service", timeout)

    def create_tenant(self, name: str, org_email: str):
        data = self._data(
            "POST",
            "/internal/tenants",
            json_body={"name": name, "org_email": org_email},
        )
        return data

    def get_tenant(self, tenant_id: str):
        return self._data("GET", f"/internal/tenants/{tenant_id}")

    def get_tenant_by_org_email(self, org_email: str):
        return self._data("GET", f"/internal/tenants/by-org-email/{org_email}")

    def add_admin(self, tenant_id: str, user_id: str) -> None:
        self._json(
            "POST",
            f"/internal/tenants/{tenant_id}/admins",
            json_body={"user_id": user_id},
        )

    def activate_tenant_account(self, tenant_id: str):
        return self._data("POST", f"/internal/tenants/{tenant_id}/activate-account")

    def accept_invitation(self, token: str, full_name: str):
        """Accept an invitation on tenant-service.

        Returns ``(user, invite)`` attribute-accessible objects mirroring what
        the in-process ``TenantService.accept_invitation`` returns.
        """
        data = self._json(
            "POST",
            "/internal/tenants/invitations/accept",
            json_body={"token": token, "full_name": full_name},
        )
        from shared.clients.internal_client import _to_namespace

        return _to_namespace(data["user"]), _to_namespace(data["invite"])