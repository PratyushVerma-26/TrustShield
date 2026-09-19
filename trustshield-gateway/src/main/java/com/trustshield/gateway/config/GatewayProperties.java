package com.trustshield.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Configuration properties for TrustShield Gateway.
 */
@ConfigurationProperties(prefix = "trustshield.gateway")
public record GatewayProperties(
        Cors cors,
        Services services
) {
    public GatewayProperties {
        cors = cors == null ? new Cors(List.of("*"), List.of("*"), List.of("*"), true) : cors;
        services = services == null ? new Services(
                "http://localhost:8083",
                "http://localhost:8084",
                "http://localhost:8085",
                "http://localhost:8086",
                "http://localhost:8087",
                "http://localhost:8088",
                "http://localhost:8089"
        ) : services;
    }

    public record Cors(
            List<String> allowedOrigins,
            List<String> allowedMethods,
            List<String> allowedHeaders,
            boolean allowCredentials
    ) {}

    public record Services(
            String phishingUrl,
            String breachUrl,
            String deepfakeUrl,
            String fakenewsUrl,
            String integrityUrl,
            String fusionUrl,
            String botUrl
    ) {}
}
