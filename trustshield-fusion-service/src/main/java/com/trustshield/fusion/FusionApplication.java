package com.trustshield.fusion;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entrypoint for the TrustShield Cross-Modal Threat Aggregation and Fusion Service.
 *
 * <p>Listens on port 8088 (and reverse-proxied via Gateway on port 8080 at {@code /api/v1/fusion/**}).
 * Correlates multi-vector incident indicators across phishing, breach, deepfake, fake news,
 * and the cryptographic integrity ledger into unified, auditable threat verdicts.
 */
@SpringBootApplication
public class FusionApplication {

    private static final Logger log = LoggerFactory.getLogger(FusionApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(FusionApplication.class, args);
        log.info("TrustShield Threat Fusion Service started on port 8088");
    }
}
