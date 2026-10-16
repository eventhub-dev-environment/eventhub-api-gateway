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
import java.util.List;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${gateway.internal-secret}")
    private String gatewayInternalSecret;

    private final List<String> openEndpointPatterns = List.of(
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/v3/api-docs",
            "/swagger-ui"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        if (openEndpointPatterns.stream().anyMatch(path::contains)) {
            // También inyectamos el secreto aquí, porque estas rutas nunca pasan
            // por la validación de JWT y por tanto nunca llegan a la rama de abajo.
            ServerHttpRequest openRequest = request.mutate()
                    .header("X-Gateway-Secret", gatewayInternalSecret)
                    .build();
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
            if (userId == null || userId.isBlank()) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            ServerHttpRequest modifiedRequest = request.mutate()
                    .headers(headers -> {
                        headers.set("X-Gateway-Secret", gatewayInternalSecret);
                        headers.set("X-User-Id", userId);
                        headers.set("X-User-Email", claims.getSubject());
                        headers.set("X-Tenant-ID", claims.get("tenantId", String.class));
                        headers.set("X-User-Roles", String.join(",", claims.get("roles", List.class)));
                    })
                    .build();

            return chain.filter(exchange.mutate().request(modifiedRequest).build());

        } catch (Exception e) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
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