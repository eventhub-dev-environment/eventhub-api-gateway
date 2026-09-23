package com.eventhub.api_gateway.infrastructure.adapter.in.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.net.URI;

@RestController
@RequestMapping("/fallback")
public class FallbackController {

    @GetMapping(value = "/auth-service", produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ResponseEntity<ProblemDetail>> authFallback() {
        return buildFallback("Auth Service Unavailable",
                "El servicio de autenticación no está disponible o tardó demasiado en responder. Por favor reintenta más tarde.");
    }

    @GetMapping(value = "/config-service", produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ResponseEntity<ProblemDetail>> configFallback() {
        return buildFallback("Config Service Unavailable",
                "El servicio de configuración no está disponible o tardó demasiado en responder. Por favor reintenta más tarde.");
    }

    @GetMapping(value = "/event-service", produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ResponseEntity<ProblemDetail>> eventFallback() {
        return buildFallback("Event Service Unavailable",
                "El servicio de eventos no está disponible o tardó demasiado en responder. Por favor reintenta más tarde.");
    }

    @GetMapping(value = "/booking-service", produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ResponseEntity<ProblemDetail>> bookingFallback() {
        return buildFallback("Booking Service Unavailable",
                "El servicio de reservas no está disponible o tardó demasiado en responder. Por favor reintenta más tarde.");
    }

    @GetMapping(value = "/payment-service", produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ResponseEntity<ProblemDetail>> paymentFallback() {
        return buildFallback("Payment Service Unavailable",
                "El servicio de pagos no está disponible temporalmente. Tu transacción no fue procesada.");
    }

    @GetMapping(value = "/notification-service", produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ResponseEntity<ProblemDetail>> notificationFallback() {
        return buildFallback("Notification Service Unavailable",
                "El servicio de notificaciones no está disponible o tardó demasiado en responder. Por favor reintenta más tarde.");
    }

    private Mono<ResponseEntity<ProblemDetail>> buildFallback(String title, String detail) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE, detail);
        problemDetail.setTitle(title);
        problemDetail.setType(URI.create("https://api.eventhub.com/errors/service-unavailable"));

        return Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(problemDetail));
    }
}