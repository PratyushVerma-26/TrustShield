package com.trustshield.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * TrustShield API Gateway.
 *
 * <p>Single origin entry-point for the React web console, Expo mobile app, and
 * WhatsApp bot. Provides centralized CORS, reverse proxying over {@link org.springframework.web.client.RestClient}
 * to individual microservices (phishing, breach, deepfake, fakenews, integrity, fusion, bot),
 * and serves static web assets on port 8080.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class GatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}
