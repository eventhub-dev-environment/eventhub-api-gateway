# EventHub API Gateway

## Authentication and tenant context

Business requests require `Authorization: Bearer <token>`. The gateway validates the JWT, removes client-supplied identity headers, and replaces them with verified user and role headers for internal services.

Tenant staff requests select an active tenant with `X-Tenant-ID`. The gateway accepts it only when the token contains a membership for that tenant, then forwards its verified roles as `X-Tenant-Roles`. Customer operations should omit `X-Tenant-ID`; the global `CUSTOMER` role does not imply membership in an organizer tenant.

Event creation and branding changes require `TENANT_ADMIN` or `EVENT_ORGANIZER` in the selected tenant. Tenant configuration requires `TENANT_ADMIN`. Global category administration and Auth tenant-role grants require `PLATFORM_ADMIN`. Booking creation requires `CUSTOMER`.
