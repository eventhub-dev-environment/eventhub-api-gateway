package com.eventhub.api_gateway.config;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAuthenticationFilterTest {

    private static final String SECRET = Base64.getEncoder().encodeToString(
            "test-secret-with-at-least-32-bytes".getBytes(StandardCharsets.UTF_8));

    private JwtAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        filter = new JwtAuthenticationFilter();
        ReflectionTestUtils.setField(filter, "secret", SECRET);
        ReflectionTestUtils.setField(filter, "gatewayInternalSecret", "gateway-secret");
    }

    @Test
    void replacesClientSuppliedUserIdWithIdFromToken() {
        ServerWebExchange exchange = exchangeWithToken(tokenWithUserId("signed-user-id"))
                .mutate()
                .request(request -> request
                        .header("X-User-Id", "spoofed-user-id")
                        .header("X-User-Email", "spoofed@example.com"))
                .build();
        AtomicReference<ServerWebExchange> forwardedExchange = new AtomicReference<>();

        filter.filter(exchange, forwarded -> {
            forwardedExchange.set(forwarded);
            return Mono.empty();
        }).block();

        HttpHeaders headers = forwardedExchange.get().getRequest().getHeaders();
        assertThat(headers.getFirst("X-User-Id")).isEqualTo("signed-user-id");
        assertThat(headers.getFirst("X-User-Email")).isEqualTo("user@example.com");
        assertThat(headers.getFirst("X-Gateway-Secret")).isEqualTo("gateway-secret");
    }

    @Test
    void rejectsTokenWithoutUserIdClaim() {
        MockServerWebExchange exchange = exchangeWithToken(tokenWithoutUserId());

        filter.filter(exchange, forwarded -> Mono.empty()).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(org.springframework.http.HttpStatus.UNAUTHORIZED);
    }

    @Test
    void forwardsTenantRolesOnlyForMembershipInRequestedTenant() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest
                .post("/api/v1/events")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenWithTenantRole())
                .header("X-Tenant-ID", "tenant-123")
                .header("X-Tenant-Roles", "PLATFORM_ADMIN")
                .header("X-User-Roles", "PLATFORM_ADMIN")
                .build());
        AtomicReference<ServerWebExchange> forwardedExchange = new AtomicReference<>();

        filter.filter(exchange, forwarded -> {
            forwardedExchange.set(forwarded);
            return Mono.empty();
        }).block();

        HttpHeaders headers = forwardedExchange.get().getRequest().getHeaders();
        assertThat(headers.getFirst("X-Tenant-ID")).isEqualTo("tenant-123");
        assertThat(headers.getFirst("X-Tenant-Roles")).isEqualTo("EVENT_ORGANIZER");
        assertThat(headers.getFirst("X-User-Roles")).isEqualTo("CUSTOMER");
    }

    @Test
    void rejectsTenantOutsideUserMemberships() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest
                .get("/api/v1/bookings")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenWithTenantRole())
                .header("X-Tenant-ID", "other-tenant")
                .build());

        filter.filter(exchange, forwarded -> Mono.empty()).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(org.springframework.http.HttpStatus.FORBIDDEN);
    }

    @Test
    void requiresTenantRoleToCreateEvents() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest
                .post("/api/v1/events")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenWithCustomerRole())
                .header("X-Tenant-ID", "tenant-123")
                .build());

        filter.filter(exchange, forwarded -> Mono.empty()).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(org.springframework.http.HttpStatus.FORBIDDEN);
    }

    @Test
    void eventOrganizerCannotReadTenantAdminConfiguration() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest
                .get("/api/v1/configs/tenant-123")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenWithTenantRole())
                .header("X-Tenant-ID", "tenant-123")
                .build());

        filter.filter(exchange, forwarded -> Mono.empty()).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(org.springframework.http.HttpStatus.FORBIDDEN);
    }

    @Test
    void doesNotTreatPathContainingRegistrationAsOpen() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/malicious/api/v1/auth/register").build());

        filter.filter(exchange, forwarded -> Mono.empty()).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(org.springframework.http.HttpStatus.UNAUTHORIZED);
    }

    private MockServerWebExchange exchangeWithToken(String token) {
        return MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/bookings")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .build());
    }

    private String tokenWithUserId(String userId) {
        return Jwts.builder()
                .subject("user@example.com")
                .claim("userId", userId)
                .claim("roles", List.of("CUSTOMER"))
                .claim("tenantMemberships", List.of(Map.of(
                        "tenantId", "tenant-123",
                        "roles", List.of("EVENT_ORGANIZER"))))
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET)))
                .compact();
    }

    private String tokenWithTenantRole() {
        return tokenWithUserId("user-123");
    }

    private String tokenWithCustomerRole() {
        return Jwts.builder()
                .subject("user@example.com")
                .claim("userId", "user-123")
                .claim("roles", List.of("CUSTOMER"))
                .claim("tenantMemberships", List.of())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET)))
                .compact();
    }

    private String tokenWithoutUserId() {
        return Jwts.builder()
                .subject("user@example.com")
                .claim("roles", List.of("CUSTOMER"))
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET)))
                .compact();
    }
}
