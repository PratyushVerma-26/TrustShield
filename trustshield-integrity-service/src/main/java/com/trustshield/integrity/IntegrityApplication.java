package com.trustshield.integrity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * TrustShield - Cryptographic Integrity Ledger Service.
 *
 * <p>Implements:
 * <ol>
 *   <li>Append-only SHA-256 hash chaining: {@code chainHash = SHA-256(previousChainHash + entryHash)}.</li>
 *   <li>Genesis linking to 64 zeros.</li>
 *   <li>Ed25519 digital signing of cumulative head hashes for non-repudiation and tamper-evidence.</li>
 *   <li>Chain audit verification pinpointing the first broken index.</li>
 * </ol>
 */
@SpringBootApplication
public class IntegrityApplication {

    public static void main(String[] args) {
        SpringApplication.run(IntegrityApplication.class, args);
    }
}
