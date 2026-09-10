# ECWF Service Responsibility Boundaries

**Version:** 1.0
**Date:** 2026-09-01
**Status:** Design (pre-implementation)

---

## Table of Contents

1. [Service Responsibility Matrix](#1-service-responsibility-matrix)
2. [Request/Response Flow](#2-requestresponse-flow)
3. [Service-to-Service Communication Flow](#3-service-to-service-communication-flow)
4. [Database Ownership](#4-database-ownership)
5. [Authentication Flow](#5-authentication-flow)
6. [Individual Registration Flow](#6-individual-registration-flow)
7. [Organization Registration Flow](#7-organization-registration-flow)
8. [Forgot Password Flow](#8-forgot-password-flow)
9. [Refresh Token Flow](#9-refresh-token-flow)
10. [Logout Flow](#10-logout-flow)
11. [Organization Profile Setup Flow](#11-organization-profile-setup-flow)
12. [Notification/Event Flow](#12-notificationevent-flow)

---

## Current Architecture Context

ECWF is currently a **FastAPI monolith** with three in-process domain services (`AuthService`, `UserService`, `TenantService`) that share a single SQLAlchemy `Session`. There are no HTTP inter-service calls, no message queues, and no event bus. All cross-service communication is direct Python method composition within a single request.

The design below **formalizes the existing boundaries** and defines the contract for each service. When the system eventually splits into independent microservices, these boundaries become the service API contracts. For now, they remain in-process calls.

---

## 1. Service Responsibility Matrix

| Capability | Auth Service | User Service | Tenant Admin Service |
|---|:---:|:---:|:---:|
| **REGISTRATION** | | | |
| Registration orchestration | **OWN** | | |
| Personal email validation | **OWN** | | |
| Business/org email validation | **OWN** | | |
| Password validation | **OWN** | | |
| Password hashing (bcrypt) | **OWN** | | |
| OTP generation & storage | **OWN** | | |
| OTP verification | **OWN** | | |
| OTP retry / expiry handling | **OWN** | | |
| OTP resend | **OWN** | | |
| OTP JWT generation (unused) | **OWN** | | |
| OTP HTTP-only cookie (unused) | **OWN** | | |
| User record creation (during reg) | Calls UserSvc | **OWN** | |
| Tenant record creation (during reg) | Calls TenantSvc | | **OWN** |
| Tenant-admin linkage (during reg) | Calls TenantSvc | | **OWN** |
| **LOGIN** | | | |
| Login orchestration | **OWN** | | |
| Access token generation | **OWN** | | |
| Refresh token generation | **OWN** | | |
| Refresh token rotation | **OWN** | | |
| Refresh token validation | **OWN** | | |
| Authentication cookies (set/clear) | **OWN** | | |
| Auth state (credentials is_active) | **OWN** | | |
| User status check (active/inactive) | Reads UserSvc | **OWN** | |
| **LOGOUT** | | | |
| Logout orchestration | **OWN** | | |
| Refresh token revocation | **OWN** | | |
| **PASSWORD MANAGEMENT** | | | |
| Forgot password orchestration | **OWN** | | |
| Password reset OTP flow | **OWN** | | |
| Password hash update | **OWN** | | |
| Post-reset token revocation | **OWN** | | |
| **AUTH MIDDLEWARE** | | | |
| Token decoding / validation | **OWN** | | |
| `get_current_user` dependency | Reads UserSvc | **OWN** | |
| `require_role` dependency | **OWN** | | |
| `require_tenant` dependency | **OWN** | | |
| **USER PROFILE** | | | |
| User creation | | **OWN** | |
| User profile (read/update) | | **OWN** | |
| Individual user data | | **OWN** | |
| Tenant user data (list/count) | | **OWN** | |
| User activation/deactivation | | **OWN** | |
| User status management | | **OWN** | |
| User roles management | | **OWN** | |
| User lookup (by email/id) | | **OWN** | |
| User/tenant relationship (tenant_id) | | **OWN** | |
| Profile setup | | **OWN** | |
| **TENANT / ORGANIZATION** | | | |
| Tenant creation | | | **OWN** |
| Tenant profile (read/update) | | | **OWN** |
| Tenant admin creation/management | | | **OWN** |
| Tenant user invitation | | | **OWN** |
| Invitation acceptance (user creation) | | Calls UserSvc | **OWN** |
| Tenant activation/deactivation | | | **OWN** |
| Tenant profile completion flag | | | **OWN** |
| Tenant admin dashboard data | | Calls UserSvc | **OWN** |
| **NOTIFICATIONS / EVENTS** | | | |
| OTP emails | Dispatches | | |
| Welcome / activation emails | Dispatches | | |
| Invitation emails | | | Dispatches |
| Password reset emails | Dispatches | | |
| Password reset confirmation | Dispatches | | |

### Key Rules

- **No circular dependencies.** Auth -> User, Auth -> Tenant, Tenant -> User. Never reverse.
- **No cross-service DB foreign keys.** Each service owns its tables. References are by string UUID.
- **No duplicate user/tenant records.** User Service is the single source of truth for user records. Tenant Admin Service is the single source of truth for tenant records.
- **Auth owns authentication state.** `AuthCredentials.is_active`, OTP records, and refresh tokens are auth-only. Auth does not own business/profile data.
- **Tenant Admin owns tenant business data.** Tenant profile, settings, admin links, and invitations are tenant-only.
- **Cross-service relationships use IDs.** `User.tenant_id` is a plain string, not a DB foreign key.

---

## 2. Request/Response Flow

All HTTP requests follow a single path through the monolith:

```
HTTP Request
    |
    v
[FastAPI Router]  (auth_routes / user_routes / tenant_routes)
    |
    v
[Pydantic Schema Validation]
    |
    v
[Route Handler]
    |--- Depends(get_db)         -> shared SQLAlchemy Session
    |--- Depends(get_current_user) -> Auth Service (token decode -> User Service lookup)
    |--- Depends(require_role)    -> Auth Service (role check on User object)
    |
    v
[Service Layer]  (AuthService / UserService / TenantService)
    |--- Business logic
    |--- Cross-service calls (direct Python method calls)
    |
    v
[Repository Layer]  (AuthRepository / UserRepository / TenantRepository)
    |--- SQL queries via SQLAlchemy ORM
    |
    v
[Database]  (SQLite dev / MySQL prod)
    |
    v
HTTP Response  (Pydantic response model serialization)
```

### Response Contract

| Endpoint Family | Success Response | Error Response |
|---|---|---|
| `POST /auth/register/*` | `201 MessageResponse` | `409 ConflictError`, `422 ValidationError_` |
| `POST /auth/otp/verify` | `200 AuthResponse` + Set-Cookie | `400 OtpInvalidError`, `429 OtpMaxAttemptsError` |
| `POST /auth/otp/resend` | `200 MessageResponse` | `400 OtpInvalidError` |
| `POST /auth/login` | `200 AuthResponse` + Set-Cookie | `401 InvalidCredentialsError`, `403 CredentialsInactiveError` |
| `POST /auth/refresh` | `200 AuthResponse` + Set-Cookie | `401 InvalidCredentialsError` |
| `POST /auth/logout` | `200 MessageResponse` + Clear-Cookie | `500 ECWFException` |
| `POST /auth/forgot-password` | `200 MessageResponse` (silent) | Never (always 200) |
| `POST /auth/reset-password` | `200 MessageResponse` | `400 OtpInvalidError` |
| `POST /auth/accept-invitation` | `201 MessageResponse` | `404 NotFoundError`, `409 ConflictError` |
| `GET /users/me` | `200 UserBase` | `401 UnauthorizedError`, `403 ForbiddenError` |
| `PATCH /users/me` | `200 UserBase` | `401 UnauthorizedError` |
| `POST /users/me/profile` | `200 UserBase` | `401 UnauthorizedError` |
| `GET /users/{id}` | `200 UserBase` | `403 ForbiddenError`, `404 NotFoundError` |
| `PATCH /users/me/status` | `200 UserBase` | `401 UnauthorizedError` |
| `GET /tenants/{id}` | `200 TenantBase` | `401 UnauthorizedError` |
| `PATCH /tenants/{id}/profile` | `200 TenantBase` | `403 ForbiddenError` |
| `PATCH /tenants/{id}/status` | `200 TenantBase` | `403 ForbiddenError` |
| `POST /tenants/{id}/invitations` | `201 TenantInvitationResponse` | `403 ForbiddenError`, `409 ConflictError` |
| `GET /tenants/{id}/invitations` | `200 [TenantInvitationResponse]` | `403 ForbiddenError` |
| `GET /tenants/{id}/dashboard` | `200 DashboardResponse` | `403 ForbiddenError` |

---

## 3. Service-to-Service Communication Flow

Since this is an in-process monolith, "inter-service communication" is direct Python method calls within the same request/transaction. The dependency graph is a **DAG** (no cycles):

```
                    AuthService
                   /          \
                  v            v
           UserService    TenantService
                              |
                              v
                         UserService
```

### Dependency Rules

| Caller | Calls | Method | Purpose |
|---|---|---|---|
| `AuthService` | `UserService` | `get_by_email(email)` | Check email uniqueness before registration |
| `AuthService` | `UserService` | `get_by_id(user_id)` | Load user for login/refresh token building |
| `AuthService` | `UserService` | `create_user(...)` | Create user record during registration |
| `AuthService` | `UserService` | `activate_user(user_id)` | Activate user after OTP verification |
| `AuthService` | `TenantService` | `create_tenant(name, org_email)` | Create tenant during org registration |
| `AuthService` | `TenantService` | `get_tenant_by_org_email(email)` | Retrieve tenant ID after creation |
| `AuthService` | `TenantService` | `add_admin(tenant_id, user_id)` | Link tenant admin during org registration |
| `AuthService` | `TenantService` | `accept_invitation(token, full_name)` | Accept invitation (creates user, marks invite) |
| `TenantService` | `UserService` | `get_by_email(email)` | Check if invitee email already registered |
| `TenantService` | `UserService` | `create_user(...)` | Create user record during invitation acceptance |
| `TenantService` | `UserService` | `dashboard_counts(tenant_id)` | Aggregate user counts for admin dashboard |

### Future Microservice Communication

When split into independent services, these in-process calls become:

| Current In-Process Call | Future Communication Method |
|---|---|
| `AuthService -> UserService.get_by_email` | HTTP API call or shared auth check |
| `AuthService -> UserService.create_user` | HTTP API call (POST /internal/users) |
| `AuthService -> TenantService.create_tenant` | HTTP API call (POST /internal/tenants) |
| `TenantService -> UserService.get_by_email` | HTTP API call |
| `TenantService -> UserService.create_user` | HTTP API call (POST /internal/users) |
| `TenantService -> UserService.dashboard_counts` | HTTP API call (GET /internal/users/counts) |

---

## 4. Database Ownership

### Current Schema (Shared Database)

All 8 tables live in a single SQLite/MySQL database. Each service's tables are marked below.

### Auth Service Tables

| Table | Owner | Purpose |
|---|---|---|
| `auth_credentials` | Auth Service | `user_id`, `email`, `password_hash`, `is_active` |
| `auth_otp` | Auth Service | OTP codes (hashed), attempts, expiry, revocation |
| `auth_refresh_tokens` | Auth Service | Refresh token hashes, revocation, rotation chain |

### User Service Tables

| Table | Owner | Purpose |
|---|---|---|
| `users` | User Service | Core user record: `id`, `email`, `full_name`, `user_type`, `role`, `status`, `tenant_id` |
| `user_profiles` | User Service | Profile data: `phone`, `avatar_url`, `bio`, `preferences` |

### Tenant Admin Service Tables

| Table | Owner | Purpose |
|---|---|---|
| `tenants` | Tenant Admin Service | Organization: `name`, `org_email`, `status`, `is_complete`, `settings` |
| `tenant_admins` | Tenant Admin Service | Admin linkage: `tenant_id`, `user_id` |
| `tenant_invitations` | Tenant Admin Service | Pending invitations: `tenant_id`, `email`, `role`, `token_hash`, expiry |

### Cross-Service ID References (No Foreign Keys)

| From Table | Column | References | Notes |
|---|---|---|---|
| `auth_credentials` | `user_id` | `users.id` | Auth owns the record; references User by ID. No DB FK constraint. |
| `auth_refresh_tokens` | `user_id` | `users.id` | Same pattern. |
| `user_profiles` | `user_id` | `users.id` | Within User Service. Has a DB unique constraint (same service). |
| `tenant_admins` | `tenant_id` | `tenants.id` | Within Tenant Admin Service. |
| `tenant_admins` | `user_id` | `users.id` | Cross-service reference. No DB FK constraint. |
| `tenant_invitations` | `tenant_id` | `tenants.id` | Within Tenant Admin Service. |
| `users` | `tenant_id` | `tenants.id` | Cross-service reference. No DB FK constraint. |

### Future Database Isolation

When services are physically separated:

- **Auth DB:** `auth_credentials`, `auth_otp`, `auth_refresh_tokens`
- **User DB:** `users`, `user_profiles`
- **Tenant DB:** `tenants`, `tenant_admins`, `tenant_invitations`

Each service's repository layer will be replaced with an HTTP client or message producer. The in-process repository classes become the API contract definition.

---

## 5. Authentication Flow

**Endpoint:** `POST /auth/login`

```
Client                          Auth Service                      User Service / Auth Repo
  |                                  |                                  |
  |-- POST /auth/login ------------->|                                  |
  |   { email, password }           |                                  |
  |                                 |-- get_by_email(email) ----------->| (User Service)
  |                                 |<-- User object or None -----------|
  |                                 |-- get_by_email(email) ----------->| (Auth Repo)
  |                                 |<-- AuthCredentials or None -------|
  |                                 |                                  |
  |                                 | [validation]                     |
  |                                 | - user + creds exist?            |
  |                                 | - password matches hash?         |
  |                                 | - creds.is_active?               |
  |                                 | - user.status == ACTIVE?         |
  |                                 |                                  |
  |                                 |-- create_access_token() -------->| (security.py)
  |                                 |<-- JWT (15min, sub=user_id,     |
  |                                 |     role, tenant_id)             |
  |                                 |                                  |
  |                                 |-- create_refresh_token() ------->| (security.py)
  |                                 |<-- JWT (7days, jti) + raw jti    |
  |                                 |                                  |
  |                                 |-- create_refresh_token() ------->| (Auth Repo)
  |                                 |   (store SHA-256(jti))           |
  |                                 |                                  |
  |<-- 200 AuthResponse ------------|                                  |
  |    { access_token, user }       |                                  |
  |    Set-Cookie: refresh_token    |                                  |
  |    (httponly, secure, 7days)    |                                  |
```

### Access Token Payload

```json
{
  "sub": "<user_id>",
  "type": "access",
  "role": "individual|tenant_user|tenant_admin|super_admin",
  "tenant_id": "<tenant_id or absent>",
  "iat": "2026-09-01T12:00:00Z",
  "exp": "2026-09-01T12:15:00Z",
  "iss": "ecwf-auth"
}
```

### Authentication Middleware (`get_current_user`)

```
Request with Authorization: Bearer <access_token>
    |
    v
_extract_bearer() -> extract token string
    |
    v
decode_token(token, expected_type=ACCESS)
    |--- Verify signature (HS256, SECRET_KEY)
    |--- Verify exp, iss
    |--- Verify type == "access"
    |
    v
Extract "sub" (user_id)
    |
    v
UserService.get_by_id(user_id)
    |--- Check user exists
    |--- Check user.status == ACTIVE
    |
    v
Return User object (attached to request)
```

### Authorization Dependencies

- **`require_role(*roles)`**: Checks `user.role in roles`. Raises `403 ForbiddenError`.
- **`require_tenant(tenant_id)`**: Checks `user.tenant_id == tenant_id`. Raises `403 ForbiddenError`. Currently defined but unused in routes.

---

## 6. Individual Registration Flow

**Endpoint:** `POST /auth/register/individual`

```
Client                          Auth Service          User Service     Tenant Service    Auth Repo    Notification
  |                                  |                    |                  |               |             |
  |-- POST /auth/register --------->|                    |                  |               |             |
  |   { email, password,            |                    |                  |               |             |
  |     full_name }                 |                    |                  |               |             |
  |                                 |                    |                  |               |             |
  |                                 | [_validate_email]  |                  |               |             |
  |                                 | [_validate_password]|                 |               |             |
  |                                 |                    |                  |               |             |
  |                                 |-- get_by_email --->|                  |               |             |
  |                                 |<-- None/user ------|                  |               |             |
  |                                 | [raise if exists]  |                  |               |             |
  |                                 |                    |                  |               |             |
  |                                 |-- create_user ---->|                  |               |             |
  |                                 |   (email, name,    |                  |               |             |
  |                                 |    INDIVIDUAL,     |                  |               |             |
  |                                 |    INDIVIDUAL,     |                  |               |             |
  |                                 |    PENDING)        |                  |               |             |
  |                                 |<-- User object ----|                  |               |             |
  |                                 |                    |                  |               |             |
  |                                 |-- create_credentials ----------------------------->|             |
  |                                 |   (user_id, email, hashed_password, is_active=F)  |             |
  |                                 |                    |                  |               |             |
  |                                 |-- _issue_otp -------------------------------------->|             |
  |                                 |   (email, EMAIL_VERIFY)                           |             |
  |                                 |   - revoke_active_otps                            |             |
  |                                 |   - generate_otp() -> "483921"                    |             |
  |                                 |   - create_otp(hash, expires, max_attempts)       |             |
  |                                 |<-- OTP code ---------------------------------------|             |
  |                                 |                    |                  |               |             |
  |                                 |-- send_otp_email --------------------------------------------->|
  |                                 |                    |                  |               |  [log/smtp] |
  |                                 |                    |                  |               |             |
  |<-- 201 MessageResponse ---------|                    |                  |               |             |
  |    "Check your email for OTP"   |                    |                  |               |             |
```

### Post-Registration: OTP Verification

**Endpoint:** `POST /auth/otp/verify`

```
Client                          Auth Service          User Service     Auth Repo    Notification
  |                                  |                    |                |             |
  |-- POST /auth/otp/verify ------->|                    |                |             |
  |   { email, otp, purpose }       |                    |                |             |
  |                                 |                    |                |             |
  |                                 |-- complete_email_verification()  |             |
  |                                 |     |                              |             |
  |                                 |     |-- verify_otp()             |             |
  |                                 |     |   get_active_otp --------->|             |
  |                                 |     |   verify_password(otp)     |             |
  |                                 |     |   [on fail: increment,     |             |
  |                                 |     |    possibly revoke+429]    |             |
  |                                 |     |   revoke_otp(otp_record)   |             |
  |                                 |     |<-- OTP record -------------|             |
  |                                 |     |                              |             |
  |                                 |     |-- get_by_email(email) ---->|             |
  |                                 |     |<-- User -------------------|             |
  |                                 |     |                              |             |
  |                                 |     |-- set_active(user_id, T) ->|             |
  |                                 |     |-- activate_user(user_id) ->|             |
  |                                 |     |                              |             |
  |                                 |     |-- send_welcome_email ---------------------->|
  |                                 |     |-- send_user_activated_email --------------->|
  |                                 |     |                              |             |
  |                                 |     |-- _build_auth_response()   |             |
  |                                 |     |   (create tokens, store    |             |
  |                                 |     |    refresh, return dict)   |             |
  |                                 |                    |                |             |
  |<-- 200 AuthResponse ------------|                    |                |             |
  |    Set-Cookie: refresh_token    |                    |                |             |
```

---

## 7. Organization Registration Flow

**Endpoint:** `POST /auth/register/tenant`

```
Client     Auth Service    Tenant Svc    User Svc    Auth Repo    Notification
  |             |              |             |            |             |
  |-- POST ---->|              |             |            |             |
  | { email,    |              |             |            |             |
  |  password,  |              |             |            |             |
  |  full_name, |              |             |            |             |
  |  org_name,  |              |             |            |             |
  |  org_email }|              |             |            |             |
  |             |              |             |            |             |
  |             | [_validate_email (personal)]           |             |
  |             | [_validate_email (org)]    |            |             |
  |             | [_validate_password]       |            |             |
  |             |              |             |            |             |
  |             |-- get_by_email ------------------------>|             |
  |             |<-- None/user ---------------------------|             |
  |             | [raise if exists]          |            |             |
  |             |              |             |            |             |
  |             |-- create_tenant ---------->|            |             |
  |             |  (org_name, org_email)     |            |             |
  |             |  [raise Conflict if dup]   |            |             |
  |             |<-- (void, created) --------|            |             |
  |             |              |             |            |             |
  |             |-- get_tenant_by_org_email >|            |             |
  |             |<-- Tenant object ----------|            |             |
  |             |              |             |            |             |
  |             |-- create_user ------------>|            |             |
  |             |  (email, name,             |            |             |
  |             |   TENANT_ADMIN,            |            |             |
  |             |   TENANT_ADMIN, PENDING,   |            |             |
  |             |   tenant_id)               |            |             |
  |             |<-- User object ------------|            |             |
  |             |              |             |            |             |
  |             |-- add_admin(tenant_id, -->|            |             |
  |             |     user_id)              |            |             |
  |             |              |             |            |             |
  |             |-- create_credentials ------------------>|             |
  |             |  (user_id, email,          |            |             |
  |             |   hashed_pw, active=F)     |            |             |
  |             |              |             |            |             |
  |             |-- _issue_otp (EMAIL_VERIFY)------------>|             |
  |             |<-- OTP code ----------------------------|             |
  |             |              |             |            |             |
  |             |-- send_otp_email ---------------------------->        |
  |             |              |             |            |  [log/smtp] |
  |             |              |             |            |             |
  |<-- 201 -----|              |             |            |             |
  | "Tenant reg |              |             |            |             |
  |  started"   |              |             |            |             |
```

### Records Created

| Table | Record | Service |
|---|---|---|
| `tenants` | name, org_email, status=PENDING | Tenant Admin |
| `users` | email, name, type=TENANT_ADMIN, role=TENANT_ADMIN, status=PENDING, tenant_id | User |
| `tenant_admins` | tenant_id, user_id | Tenant Admin |
| `auth_credentials` | user_id, email, password_hash, is_active=False | Auth |
| `auth_otp` | email, purpose=EMAIL_VERIFY, hashed OTP | Auth |

---

## 8. Forgot Password Flow

### Step 1: Request Reset OTP

**Endpoint:** `POST /auth/forgot-password`

```
Client                 Auth Service          User Svc     Auth Repo    Notification
  |                        |                    |              |             |
  |-- POST --------------->|                    |              |             |
  | { email }              |                    |              |             |
  |                        |                    |              |             |
  |                        |-- get_by_email --->|              |             |
  |                        |<-- User/None ------|              |             |
  |                        |                    |              |             |
  |                        | [if None: return silently, no error]          |
  |                        |                    |              |             |
  |                        |-- _issue_otp(PASSWORD_RESET) --->|             |
  |                        |   revoke_active_otps             |             |
  |                        |   generate_otp()                 |             |
  |                        |   create_otp(hash, expires)      |             |
  |                        |<-- OTP code ---------------------|             |
  |                        |                    |              |             |
  |                        |-- send_password_reset_email --------------->   |
  |                        |                    |              |  [log/smtp] |
  |                        |                    |              |             |
  |<-- 200 MessageResponse |                    |              |             |
  | "If email exists,      |                    |              |             |
  |  OTP has been sent"    |                    |              |             |
```

### Step 2: Reset Password with OTP

**Endpoint:** `POST /auth/reset-password`

```
Client                 Auth Service          User Svc     Auth Repo    Notification
  |                        |                    |              |             |
  |-- POST --------------->|                    |              |             |
  | { email, otp,          |                    |              |             |
  |   new_password }       |                    |              |             |
  |                        |                    |              |             |
  |                        |-- _validate_password(new_password)             |
  |                        |                    |              |             |
  |                        |-- verify_otp(email, otp, PASSWORD_RESET) -->  |
  |                        |   get_active_otp -->|              |             |
  |                        |   verify_password   |              |             |
  |                        |   revoke_otp        |              |             |
  |                        |<-- OTP record ------|              |             |
  |                        |                    |              |             |
  |                        |-- get_by_email --->|              |             |
  |                        |<-- User -----------|              |             |
  |                        |                    |              |             |
  |                        |-- update_password(hash) ----------------->    |
  |                        |                    |              |             |
  |                        |-- revoke_all_user_tokens(user_id) -------->   |
  |                        |                    |              |             |
  |                        |-- send_password_reset_confirmation -------->  |
  |                        |                    |              |  [log/smtp] |
  |                        |                    |              |             |
  |<-- 200 MessageResponse |                    |              |             |
  | "Password reset        |                    |              |             |
  |  successfully"         |                    |              |             |
```

### Security Properties

- Forgot password always returns `200` regardless of whether the email exists (prevents user enumeration).
- After successful reset, all refresh tokens are revoked (forces re-login on all devices).
- Password reset confirmation email is sent for account-security notification.

---

## 9. Refresh Token Flow

**Endpoint:** `POST /auth/refresh`

```
Client                 Auth Service          User Svc     Auth Repo
  |                        |                    |              |
  |-- POST /auth/refresh ->|                    |              |
  | Cookie: ecwf_refresh_token                  |              |
  |                        |                    |              |
  |                        |-- decode_token(refresh_token,     |
  |                        |   expected_type=None)             |
  |                        | [verify type == "refresh"]        |
  |                        | [extract user_id, jti]            |
  |                        |                    |              |
  |                        |-- get_refresh_token(hash_jti(jti)) ---------->|
  |                        |<-- AuthRefreshToken record -------------------|
  |                        | [validate: not revoked, not expired]          |
  |                        |                    |              |
  |                        |-- get_by_id(user_id) ->|          |
  |                        |<-- User object -------|          |
  |                        | [validate: status == ACTIVE]     |
  |                        |                    |              |
  |                        |-- revoke_refresh_token(record) ----------->   |
  |                        |                    |              |
  |                        |-- create_access_token(user_id, role, tenant_id)|
  |                        |-- create_refresh_token(user_id) ->|           |
  |                        |<-- new JWT + new jti -------------|           |
  |                        |                    |              |
  |                        |-- create_refresh_token(new_hash,   |
  |                        |   rotated_from=old_record_id) --->|           |
  |                        |                    |              |
  |<-- 200 AuthResponse ---|                    |              |
  | Set-Cookie: new refresh_token              |              |
```

### Rotation Chain

```
Token v1 (jti=abc)
  |-- used for refresh
  |-- revoked, rotated_from=None
  |
  v
Token v2 (jti=def)    <- rotated_from=token_v1.id
  |-- used for refresh
  |-- revoked, rotated_from=token_v2.id
  |
  v
Token v3 (jti=ghi)    <- rotated_from=token_v2.id
  ...
```

### Refresh Cookie Configuration

| Property | Value |
|---|---|
| Name | `ecwf_refresh_token` |
| HttpOnly | `true` |
| Secure | Configurable (`COOKIE_SECURE`, default `true`) |
| SameSite | Configurable (`COOKIE_SAMESITE`, default `strict`) |
| Path | `/auth` |
| MaxAge | `REFRESH_TOKEN_EXPIRE_DAYS * 86400` (default: 7 days) |

---

## 10. Logout Flow

**Endpoint:** `POST /auth/logout`

```
Client                 Auth Service          User Svc     Auth Repo
  |                        |                    |              |
  |-- POST /auth/logout -->|                    |              |
  | Cookie: ecwf_refresh_token (may be absent) |              |
  |                        |                    |              |
  |                        | [if no cookie: skip revocation]  |
  |                        |                    |              |
  |                        |-- decode_token(refresh_token)     |
  |                        | [extract user_id]  |              |
  |                        | [if invalid: silently skip]       |
  |                        |                    |              |
  |                        |-- revoke_all_user_tokens(user_id) ---------->|
  |                        | [marks ALL active refresh tokens             |
  |                        |  for this user as revoked]                   |
  |                        |                    |              |
  |<-- 200 MessageResponse |                    |              |
  | Clear-Cookie: ecwf_refresh_token           |              |
  | "Logged out"           |                    |              |
```

### Logout Behavior

- **Always 200.** Even if the refresh token is absent, invalid, or already revoked, logout succeeds.
- **Revokes all user tokens.** Not just the current token, but every active refresh token for the user. This invalidates all sessions.
- **Client must clear the access token.** The access token (Bearer header) has a short TTL (15 min) and will expire naturally. Server-side revocation of access tokens is not implemented (by design — short-lived tokens).

---

## 11. Organization Profile Setup Flow

**Endpoint:** `PATCH /tenants/{tenant_id}/profile`

```
Client              Tenant Service          Tenant Repo
  |                      |                      |
  |-- PATCH ----------->|                      |
  | { tenant_id,         |                      |
  |   name?,             |                      |
  |   org_email?,        |                      |
  |   settings? }        |                      |
  |                      |                      |
  | [Depends(require_role(TENANT_ADMIN))]       |
  |                      |                      |
  |                      |-- get_tenant ------>|
  |                      |<-- Tenant object ---|
  |                      | [raise NotFound]    |
  |                      |                      |
  |                      |-- update_tenant --->|
  |                      |  (name, org_email,  |
  |                      |   settings)         |
  |                      |<-- updated Tenant --|
  |                      |                      |
  |                      |-- update_tenant --->|
  |                      |  (is_complete=True)  |
  |                      |<-- updated Tenant --|
  |                      |                      |
  |<-- 200 TenantBase ---|                      |
  | { id, name, org_email,                     |
  |   status, is_complete=True }               |
```

### Tenant Admin Dashboard

**Endpoint:** `GET /tenants/{tenant_id}/dashboard`

```
Client     Tenant Service    User Svc    Tenant Repo
  |             |               |             |
  |-- GET ----->|               |             |
  |             |               |             |
  | [require_role(TENANT_ADMIN)]             |
  |             |               |             |
  |             |-- is_admin -->|             |
  |             |<-- true ------|             |
  |             |               |             |
  |             |-- get_tenant ->|             |
  |             |<-- Tenant ----|             |
  |             |               |             |
  |             |-- dashboard_counts -------->|
  |             |<-- { total, active } -------|
  |             |               |             |
  |             |-- count_pending_invitations >|
  |             |<-- count -------------------|
  |             |               |             |
  |<-- 200 DashboardResponse   |             |
```

---

## 12. Notification/Event Flow

### Current Implementation

Notifications are synchronous email sends via `NotificationService`. There is no event bus, no message queue, and no async event processing. The service has a module-level singleton instance.

```
notification_service = NotificationService()
```

### Notification Triggers

| Trigger | Called From | Method | Email Type |
|---|---|---|---|
| Individual registration | `AuthService.register_individual` | `send_otp_email` | Email verification OTP |
| Tenant registration | `AuthService.register_tenant` | `send_otp_email` | Email verification OTP |
| OTP resend | `AuthService.resend_otp` | `send_otp_email` or `send_password_reset_email` | OTP (purpose-dependent) |
| Email verified | `AuthService.complete_email_verification` | `send_welcome_email` | Welcome |
| Email verified | `AuthService.complete_email_verification` | `send_user_activated_email` | Account activated |
| Invitation sent | `tenant_routes.invite_user` | `send_invite_email` | Invitation link |
| Password reset request | `AuthService.forgot_password` | `send_password_reset_email` | Password reset OTP |
| Password reset complete | `AuthService.reset_password` | `send_password_reset_confirmation` | Password changed |
| Invitation accepted | `AuthService.accept_invitation` | `send_otp_email` | Email verification OTP (for new invited user) |

### Notification Delivery

```
NotificationService
    |
    |-- SMTP configured (SMTP_HOST set)?
    |     YES -> smtplib.SMTP -> STARTTLS -> sendmail
    |     NO  -> logger.info("[email:dev] To=... Subject=... Body=...")
```

### Future Event Architecture

When the monolith splits, notifications should move to an event-driven model:

```
Service publishes event
    |
    v
Message Queue (e.g., Redis Streams, RabbitMQ, or internal pub/sub)
    |
    v
Notification Consumer Service
    |
    v
Email / SMS / Push delivery
```

**Proposed Events:**

| Event | Publisher | Consumers |
|---|---|---|
| `user.registered` | Auth Service | Notification Service (send OTP) |
| `user.activated` | Auth Service | Notification Service (welcome email) |
| `user.password_reset_requested` | Auth Service | Notification Service (reset OTP) |
| `user.password_reset_completed` | Auth Service | Notification Service (confirmation) |
| `tenant.invitation_sent` | Tenant Admin Service | Notification Service (invite email) |
| `tenant.invitation_accepted` | Tenant Admin Service | Notification Service (OTP for invited user) |

### Notification Ownership Rule

The **service that triggers the business action** owns the decision to send a notification. The notification service is a **delivery mechanism only** — it does not contain business logic about when to send emails.

| Service | Decides to send | Notification Service |
|---|---|---|
| Auth Service | OTP, welcome, activation, reset | Delivers email |
| Tenant Admin Service | Invitation | Delivers email |

---

## Summary of Architectural Rules

1. **No circular service dependencies.** The dependency graph is: `Auth -> User`, `Auth -> Tenant`, `Tenant -> User`. No reverse edges.
2. **No cross-service DB foreign keys.** All cross-service references are by string UUID. DB-level FK constraints exist only within a single service's tables (e.g., `user_profiles.user_id` -> `users.id`).
3. **Services own their database tables.** Auth owns `auth_*` tables, User owns `users`/`user_profiles`, Tenant owns `tenants`/`tenant_admins`/`tenant_invitations`.
4. **Single source of truth.** User Service owns all user records. Tenant Admin Service owns all tenant records. Auth Service owns all authentication state. No duplicates.
5. **Auth does not own business/profile data.** Password hashes, OTP records, and refresh tokens are auth-only. User profile data (name, phone, bio) belongs to User Service.
6. **Tenant Admin Service owns tenant/organization business data.** Tenant profile, settings, admin links, and invitations are tenant-only.
7. **Cross-service relationships use IDs + service APIs.** In the current monolith, these are direct method calls. In a future microservice split, they become HTTP API calls or event-driven eventual consistency.
8. **Shared DB session for now.** All services use the same SQLAlchemy `Session` per request, which means the current architecture is transactional (atomic commit/rollback across all services in a single request). This changes when services get their own databases.
