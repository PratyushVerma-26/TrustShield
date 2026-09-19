package com.trustshield.breach;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import com.trustshield.breach.config.BreachProperties;

/**
 * Entrypoint for the TrustShield Personal Data Breach Monitor service.
 *
 * <p>Provides secure k-anonymous password exposure verification via the HaveIBeenPwned range API
 * and privacy-conscious email breach lookup.
 */
@SpringBootApplication
@EnableConfigurationProperties(BreachProperties.class)
public class BreachApplication {

    public static void main(String[] args) {
        SpringApplication.run(BreachApplication.class, args);
    }
}
