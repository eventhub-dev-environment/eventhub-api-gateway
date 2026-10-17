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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtAuthenticationFilterTest {

    private static final String SECRET = Base64.getEncoder().encodeToString(
            "test-secret-with-at-least-32-bytes".getBytes(StandardCharsets.UTF_8));

    private JwtAuthenticationFilter filter;
    private TokenAuthorizationClient tokenAuthorizationClient;

    @BeforeEach
    void setUp() {
        tokenAuthorizationClient = mock(TokenAuthorizationClient.class);
        when(tokenAuthorizationClient.isCurrent(anyString())).thenReturn(Mono.just(true));
        filter = new JwtAuthenticationFilter(tokenAuthorizationClient);
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
    void rejectsTokenWhenAuthServiceReportsRevokedAuthorization() {
        when(tokenAuthorizationClient.isCurrent(anyString())).thenReturn(Mono.just(false));
        MockServerWebExchange exchange = exchangeWithToken(tokenWithTenantRole());
        AtomicReference<ServerWebExchange> forwardedExchange = new AtomicReference<>();

        filter.filter(exchange, forwarded -> {
            forwardedExchange.set(forwarded);
            return Mono.empty();
        }).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(org.springframework.http.HttpStatus.UNAUTHORIZED);
        assertThat(forwardedExchange.get()).isNull();
    }

    @Test
    void failsClosedWhenAuthServiceCannotValidateAuthorization() {
        when(tokenAuthorizationClient.isCurrent(anyString()))
                .thenReturn(Mono.error(new IllegalStateException("Auth Service unavailable")));
        MockServerWebExchange exchange = exchangeWithToken(tokenWithTenantRole());
        AtomicReference<ServerWebExchange> forwardedExchange = new AtomicReference<>();

        filter.filter(exchange, forwarded -> {
            forwardedExchange.set(forwarded);
            return Mono.empty();
        }).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(
                org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(forwardedExchange.get()).isNull();
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

    @Test
    void forwardsPaymentWebhookWithoutJwtButAddsGatewaySecret() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest
                .post("/api/v1/payments/webhook")
                .header("X-EventHub-Signature", "sha256=signature")
                .header("X-User-Id", "spoofed-user")
                .build());
        AtomicReference<ServerWebExchange> forwardedExchange = new AtomicReference<>();

        filter.filter(exchange, forwarded -> {
            forwardedExchange.set(forwarded);
            return Mono.empty();
        }).block();

        HttpHeaders headers = forwardedExchange.get().getRequest().getHeaders();
        assertThat(headers.getFirst("X-Gateway-Secret")).isEqualTo("gateway-secret");
        assertThat(headers.getFirst("X-User-Id")).isNull();
        assertThat(headers.getFirst("X-EventHub-Signature")).isEqualTo("sha256=signature");
    }

    @Test
    void forwardsStripeWebhookWithoutJwtAndPreservesStripeSignature() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest
                .post("/api/v1/payments/webhook/stripe")
                .header("Stripe-Signature", "t=123,v1=signature")
                .header("X-User-Id", "spoofed-user")
                .build());
        AtomicReference<ServerWebExchange> forwardedExchange = new AtomicReference<>();

        filter.filter(exchange, forwarded -> {
            forwardedExchange.set(forwarded);
            return Mono.empty();
        }).block();

        HttpHeaders headers = forwardedExchange.get().getRequest().getHeaders();
        assertThat(headers.getFirst("X-Gateway-Secret")).isEqualTo("gateway-secret");
        assertThat(headers.getFirst("X-User-Id")).isNull();
        assertThat(headers.getFirst("Stripe-Signature")).isEqualTo("t=123,v1=signature");
    }

    @Test
    void requiresCustomerRoleToCreateStripeCheckoutSession() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest
                .post("/api/v1/payments/checkout-session")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenWithoutCustomerRole())
                .build());

        filter.filter(exchange, forwarded -> Mono.empty()).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(org.springframework.http.HttpStatus.FORBIDDEN);
    }

    @Test
    void requiresCustomerRoleToCancelBooking() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest
                .post("/api/v1/bookings/booking-123/cancel")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenWithoutCustomerRole())
                .build());

        filter.filter(exchange, forwarded -> Mono.empty()).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(org.springframework.http.HttpStatus.FORBIDDEN);
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

    private String tokenWithoutCustomerRole() {
        return Jwts.builder()
                .subject("staff@example.com")
                .claim("userId", "staff-123")
                .claim("roles", List.of("EVENT_ORGANIZER"))
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
