package com.trustshield.breach;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import com.trustshield.breach.config.BreachProperties;

/**
 * Personal Data Breach Monitor.
 *
 * <p>Answers two different questions that the original project draft treated as
 * one, and which have very different privacy properties:
 *
 * <ol>
 *   <li><strong>"Has this password appeared in a known breach corpus?"</strong> —
 *       answerable with genuine k-anonymity via the Pwned Passwords range API.
 *       The password never leaves the process and neither does its full hash.
 *       Needs no API key.</li>
 *   <li><strong>"Has this email address appeared in known breaches?"</strong> —
 *       <em>not</em> k-anonymous. The HIBP breached-account endpoint requires a
 *       paid API key and receives the full address. Disabled by default.</li>
 * </ol>
 *
 * <p>Conflating the two is a substantive error, not a naming quibble: it would
 * mean claiming a privacy guarantee for an operation that does not have one. The
 * distinction is enforced in code by keeping the two clients apart and by
 * reporting {@code kAnonymous} per check in the API response.
 *
 * <p>The Aadhaar partial-pattern matching described in the original design has
 * been removed deliberately. Storing or pattern-matching Aadhaar numbers engages
 * s.29 of the Aadhaar Act 2016 and the purpose-limitation duties of the DPDP Act
 * 2023, and no part of this project needs it to demonstrate breach monitoring.
 */
@SpringBootApplication
@EnableConfigurationProperties(BreachProperties.class)
public class BreachApplication {

    public static void main(String[] args) {
        SpringApplication.run(BreachApplication.class, args);
    }
}
