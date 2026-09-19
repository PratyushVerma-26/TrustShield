package com.trustshield.bot;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entrypoint for the TrustShield Conversational Cyber-Defense Bot Service.
 *
 * <p>Listens on port 8089 (and reverse-proxied via Gateway on port 8080 at {@code /api/v1/bot/**} and {@code /webhook/**}).
 * Acts as the messaging integration gateway for WhatsApp, Telegram, and mobile chat clients,
 * dispatching security scans to specialized detectors and rendering human-readable safety assessments.
 */
@SpringBootApplication
public class BotApplication {

    private static final Logger log = LoggerFactory.getLogger(BotApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(BotApplication.class, args);
        log.info("TrustShield Conversational Bot Service started on port 8089");
    }
}
