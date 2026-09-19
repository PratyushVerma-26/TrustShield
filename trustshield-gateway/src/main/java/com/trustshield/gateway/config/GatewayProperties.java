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
        if (cors == null) {
            cors = new Cors(
                    List.of("http://localhost:5173", "http://localhost:3000", "http://localhost:8080", "http://127.0.0.1:5173", "http://127.0.0.1:3000", "http://127.0.0.1:8080"),
                    List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"),
                    List.of("*"),
                    true
            );
        } else if (cors.allowedOrigins() != null && cors.allowedOrigins().contains("*") && cors.allowCredentials()) {
            // OWASP & W3C CORS fix: Wildcard origin with allowCredentials=true is an invalid/insecure configuration
            cors = new Cors(cors.allowedOrigins(), cors.allowedMethods(), cors.allowedHeaders(), false);
        }
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
