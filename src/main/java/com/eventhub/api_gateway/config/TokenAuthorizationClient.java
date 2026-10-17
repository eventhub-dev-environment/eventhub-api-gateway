package com.eventhub.api_gateway.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Component
@Slf4j
public class TokenAuthorizationClient {

    private static final Duration TIMEOUT = Duration.ofSeconds(2);
    private final WebClient webClient;
    private final String gatewayInternalSecret;

    public TokenAuthorizationClient(
            WebClient.Builder webClientBuilder,
            @Value("${auth.service.base-url:http://auth-service:8082}") String authServiceBaseUrl,
            @Value("${gateway.internal-secret}") String gatewayInternalSecret) {
        this.webClient = webClientBuilder.baseUrl(authServiceBaseUrl).build();
        this.gatewayInternalSecret = gatewayInternalSecret;
    }

    public Mono<Boolean> isCurrent(String token) {
        return webClient.post()
                .uri("/internal/v1/authz/validate")
                .header("X-Gateway-Secret", gatewayInternalSecret)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchangeToMono(response -> {
                    if (response.statusCode().is2xxSuccessful()) {
                        return Mono.just(true);
                    }
                    if (response.statusCode().value() == 401) {
                        return Mono.just(false);
                    }
                    return response.createException().flatMap(Mono::error);
                })
                .timeout(TIMEOUT)
                .doOnError(exception -> log.error(
                        "No fue posible consultar la vigencia de permisos en Auth Service", exception));
    }
}
