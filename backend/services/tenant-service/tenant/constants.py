"""Shared domain constants for tenant-service.

The enum classes are imported from the collocated auth-service library package
so identity is preserved across services in the same deployment (monolith tests
and microservices runtime share the same values).
"""
from app.core.constants import TenantStatus, UserRole, UserStatus, UserType

__all__ = ["TenantStatus", "UserRole", "UserStatus", "UserType"]