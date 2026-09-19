package com.trustshield.phishing;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Phishing and Fake Website Shield service.
 *
 * <p>Classifies URLs using a local lexical model, optionally corroborated by
 * external reputation APIs. Runs on port 8083 by default.
 */
@SpringBootApplication
public class PhishingApplication {

    public static void main(String[] args) {
        SpringApplication.run(PhishingApplication.class, args);
    }
}
