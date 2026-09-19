package com.trustshield.fakenews;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * TrustShield - Misinformation and Fact Verification Service.
 *
 * <p>Implements:
 * <ol>
 *   <li>Google Fact Check Tools API client for direct claim review corroboration (primary evidence).</li>
 *   <li>Offline 64-bit SimHash near-duplicate matcher against bundled debunked claims catalog.</li>
 *   <li>Secondary linguistic style analyzer (capitalisation ratio, sensational punctuation, absolutist terms, unsourced attribution).</li>
 * </ol>
 *
 * <p>Enforces core invariants:
 * <ul>
 *   <li>Inverted evidence weighting: corroboration is primary; linguistic style is secondary.</li>
 *   <li>Style score is hard-capped at 55 and can never reach {@code ThreatLevel.DANGEROUS} on its own.</li>
 *   <li>Refusal to declare unverified claims "safe" or "true" when external fact-checkers were not reached.</li>
 * </ul>
 */
@SpringBootApplication
public class FakenewsApplication {

    public static void main(String[] args) {
        SpringApplication.run(FakenewsApplication.class, args);
    }
}
