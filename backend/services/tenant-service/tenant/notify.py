"""Notification dependency for tenant-service.

- ``monolith`` mode: the in-process notification singleton shared with the
  composed auth application (tests use this).
- ``microservices`` mode: an HTTP client that calls the notification-service
  internal email API.
"""
import logging

from tenant.core import tenant_settings

logger = logging.getLogger("ecwf.tenant.notify")

if tenant_settings.SERVICE_MODE == "monolith":
    from notification.services.notification_service import notification_service
else:
    from shared.clients.notification_client import NotificationClient

    notification_service = NotificationClient(
        base_url=tenant_settings.NOTIFICATION_SERVICE_URL,
        api_key=tenant_settings.INTERNAL_API_KEY,
    )