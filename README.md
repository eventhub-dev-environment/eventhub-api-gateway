# EventHub API Gateway

## Authentication and tenant context

Business requests require `Authorization: Bearer <token>`. The gateway validates the JWT, removes client-supplied identity headers, and replaces them with verified user and role headers for internal services.

Tenant staff requests select an active tenant with `X-Tenant-ID`. The gateway accepts it only when the token contains a membership for that tenant, then forwards its verified roles as `X-Tenant-Roles`. Customer operations should omit `X-Tenant-ID`; the global `CUSTOMER` role does not imply membership in an organizer tenant.

Event creation and branding changes require `TENANT_ADMIN` or `EVENT_ORGANIZER` in the selected tenant. Tenant configuration requires `TENANT_ADMIN`. Global category administration and Auth tenant-role grants require `PLATFORM_ADMIN`. Booking creation requires `CUSTOMER`.

For every protected request, the gateway also asks Auth Service to verify that the signed token still matches the user's current enabled status and persisted global and tenant roles. The internal URL uses `auth.service.base-url` (default `http://auth-service:8082`), and the request is protected with the same `gateway.internal-secret` configured in Auth Service. Revoking a role or disabling an account invalidates existing tokens immediately; newly granted roles require a fresh login. If Auth Service reports a stale or invalid token, the gateway returns `401`. If Auth Service is unavailable or does not respond within two seconds, the gateway fails closed with `503`; open login, registration, documentation, and payment webhook endpoints are not subject to this online token check.
