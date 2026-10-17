package com.eventhub.api_gateway.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private static final String USER_ID_HEADER = "X-User-Id";
    private static final String USER_EMAIL_HEADER = "X-User-Email";
    private static final String USER_ROLES_HEADER = "X-User-Roles";
    private static final String TENANT_ROLES_HEADER = "X-Tenant-Roles";
    private static final String TENANT_ID_HEADER = "X-Tenant-ID";
    private static final String GATEWAY_SECRET_HEADER = "X-Gateway-Secret";

    @Value("${jwt.secret}")
    private String secret;

    @Value("${gateway.internal-secret}")
    private String gatewayInternalSecret;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        if (isOpenEndpoint(path)) {
            ServerHttpRequest openRequest = request.mutate().headers(headers -> {
                clearIdentityHeaders(headers);
                headers.set(GATEWAY_SECRET_HEADER, gatewayInternalSecret);
            }).build();
            return chain.filter(exchange.mutate().request(openRequest).build());
        }

        if (!request.getHeaders().containsHeader(HttpHeaders.AUTHORIZATION)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);

        try {
            Claims claims = validateAndExtractClaims(token);
            String userId = claims.get("userId", String.class);
            String email = claims.getSubject();
            List<String> roles = readStringList(claims.get("roles"), true);
            List<TenantMembership> memberships = readTenantMemberships(claims.get("tenantMemberships"));
            if (userId == null || userId.isBlank() || email == null || email.isBlank()) {
                return reject(exchange, HttpStatus.UNAUTHORIZED);
            }

            boolean platformAdmin = roles.contains("PLATFORM_ADMIN");
            String requestedTenant = request.getHeaders().getFirst(TENANT_ID_HEADER);
            if (requestedTenant != null && !requestedTenant.isBlank()
                    && !platformAdmin && membershipFor(memberships, requestedTenant) == null) {
                return reject(exchange, HttpStatus.FORBIDDEN);
            }
            if (requiresPlatformAdmin(request) && !platformAdmin) {
                return reject(exchange, HttpStatus.FORBIDDEN);
            }
            if (requiresTenantStaff(request)
                    && !hasTenantRole(memberships, requestedTenant, "TENANT_ADMIN", "EVENT_ORGANIZER")
                    && !platformAdmin) {
                return reject(exchange, HttpStatus.FORBIDDEN);
            }
            if (requiresTenantAdmin(request)
                    && !hasTenantRole(memberships, requestedTenant, "TENANT_ADMIN")
                    && !platformAdmin) {
                return reject(exchange, HttpStatus.FORBIDDEN);
            }
            if (requiresCustomer(request) && !roles.contains("CUSTOMER")) {
                return reject(exchange, HttpStatus.FORBIDDEN);
            }

            ServerHttpRequest modifiedRequest = request.mutate().headers(headers -> {
                clearIdentityHeaders(headers);
                headers.set(GATEWAY_SECRET_HEADER, gatewayInternalSecret);
                headers.set(USER_ID_HEADER, userId);
                headers.set(USER_EMAIL_HEADER, email);
                headers.set(USER_ROLES_HEADER, String.join(",", roles));
                TenantMembership activeMembership = requestedTenant == null || requestedTenant.isBlank()
                        ? null
                        : membershipFor(memberships, requestedTenant);
                headers.set(TENANT_ROLES_HEADER, activeMembership == null
                        ? ""
                        : String.join(",", activeMembership.roles()));
                if (requestedTenant == null || requestedTenant.isBlank()) {
                    headers.remove(TENANT_ID_HEADER);
                } else {
                    headers.set(TENANT_ID_HEADER, requestedTenant);
                }
            }).build();

            return chain.filter(exchange.mutate().request(modifiedRequest).build());

        } catch (Exception e) {
            return reject(exchange, HttpStatus.UNAUTHORIZED);
        }
    }

    private boolean isOpenEndpoint(String path) {
        return path.equals("/api/v1/auth/login")
                || path.equals("/api/v1/auth/register")
                || path.equals("/api/v1/payments/webhook")
                || path.equals("/api/v1/payments/webhook/stripe")
                || isPathOrChild(path, "/v3/api-docs")
                || isPathOrChild(path, "/api/v1/auth/v3/api-docs")
                || isPathOrChild(path, "/api/v1/events/v3/api-docs")
                || isPathOrChild(path, "/api/v1/bookings/v3/api-docs")
                || isPathOrChild(path, "/api/v1/configs/v3/api-docs")
                || isPathOrChild(path, "/api/v1/payments/v3/api-docs")
                || isPathOrChild(path, "/api/v1/notifications/v3/api-docs")
                || isPathOrChild(path, "/swagger-ui")
                || isPathOrChild(path, "/webjars");
    }

    private boolean isPathOrChild(String path, String prefix) {
        return path.equals(prefix) || path.startsWith(prefix + "/");
    }

    private boolean requiresPlatformAdmin(ServerHttpRequest request) {
        String path = request.getURI().getPath();
        return path.startsWith("/api/v1/auth/admin/")
                || (path.equals("/api/v1/categories") && request.getMethod() == org.springframework.http.HttpMethod.POST)
                || (path.startsWith("/api/v1/categories/") && request.getMethod() == org.springframework.http.HttpMethod.PUT);
    }

    private boolean requiresTenantStaff(ServerHttpRequest request) {
        String path = request.getURI().getPath();
        return (path.equals("/api/v1/events") && request.getMethod() == org.springframework.http.HttpMethod.POST)
                || (path.matches("/api/v1/events/[^/]+/branding/(logo|banner)")
                    && request.getMethod() == org.springframework.http.HttpMethod.POST)
                || (path.equals("/api/v1/bookings/tickets/validate")
                    && request.getMethod() == org.springframework.http.HttpMethod.POST);
    }

    private boolean requiresTenantAdmin(ServerHttpRequest request) {
        String path = request.getURI().getPath();
        return (path.equals("/api/v1/configs") && request.getMethod() == org.springframework.http.HttpMethod.POST)
                || (path.matches("/api/v1/configs/[^/]+")
                    && request.getMethod() == org.springframework.http.HttpMethod.GET);
    }

    private boolean requiresCustomer(ServerHttpRequest request) {
        String path = request.getURI().getPath();
        return (path.equals("/api/v1/bookings")
                || path.matches("/api/v1/bookings/[^/]+/cancel")
                || path.equals("/api/v1/payments/checkout-session"))
                && request.getMethod() == org.springframework.http.HttpMethod.POST;
    }

    private boolean hasTenantRole(List<TenantMembership> memberships, String tenantId, String... roles) {
        if (tenantId == null || tenantId.isBlank()) {
            return false;
        }
        TenantMembership membership = membershipFor(memberships, tenantId);
        return membership != null && membership.roles().stream().anyMatch(Set.of(roles)::contains);
    }

    private TenantMembership membershipFor(List<TenantMembership> memberships, String tenantId) {
        return memberships.stream()
                .filter(membership -> membership.tenantId().equals(tenantId))
                .findFirst()
                .orElse(null);
    }

    private List<String> readStringList(Object value, boolean required) {
        if (value == null && !required) {
            return List.of();
        }
        if (!(value instanceof List<?> values)) {
            throw new IllegalArgumentException("JWT list claim is invalid");
        }

        List<String> result = new ArrayList<>();
        for (Object item : values) {
            if (!(item instanceof String string) || string.isBlank()) {
                throw new IllegalArgumentException("JWT list claim contains an invalid value");
            }
            result.add(string);
        }
        return result;
    }

    private List<TenantMembership> readTenantMemberships(Object value) {
        if (value == null) {
            return List.of();
        }
        if (!(value instanceof List<?> values)) {
            throw new IllegalArgumentException("JWT tenant memberships claim is invalid");
        }

        List<TenantMembership> memberships = new ArrayList<>();
        for (Object item : values) {
            if (!(item instanceof Map<?, ?> membership)) {
                throw new IllegalArgumentException("JWT tenant membership is invalid");
            }
            Object tenantId = membership.get("tenantId");
            if (!(tenantId instanceof String tenant) || tenant.isBlank()) {
                throw new IllegalArgumentException("JWT tenant ID is invalid");
            }
            memberships.add(new TenantMembership(tenant, readStringList(membership.get("roles"), true)));
        }
        return memberships;
    }

    private Mono<Void> reject(ServerWebExchange exchange, HttpStatus status) {
        exchange.getResponse().setStatusCode(status);
        return exchange.getResponse().setComplete();
    }

    private void clearIdentityHeaders(HttpHeaders headers) {
        headers.remove(USER_ID_HEADER);
        headers.remove(USER_EMAIL_HEADER);
        headers.remove(USER_ROLES_HEADER);
        headers.remove(TENANT_ROLES_HEADER);
        headers.remove(TENANT_ID_HEADER);
        headers.remove(GATEWAY_SECRET_HEADER);
    }

    private record TenantMembership(String tenantId, List<String> roles) {
    }

    private Claims validateAndExtractClaims(String token) {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        SecretKey key = Keys.hmacShaKeyFor(keyBytes);

        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    @Override
    public int getOrder() {
        return -1;
    }
}