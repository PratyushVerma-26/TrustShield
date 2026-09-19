package com.trustshield.breach.hibp;

import java.time.Duration;
import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import com.trustshield.breach.config.BreachProperties;
import com.trustshield.common.util.HashUtils;

/**
 * Client for the HaveIBeenPwned Pwned Passwords range API, implementing k-anonymity.
 *
 * <p>Execution Protocol:
 * <ol>
 *   <li>Compute local SHA-1 digest of candidate password: {@link HashUtils#sha1HexUpper}.</li>
 *   <li>Transmit only the first 5 hex characters as a bucket prefix: {@code GET /range/{prefix}}.</li>
 *   <li>The remote API returns hashed suffixes belonging to the prefix bucket with occurrence counts.</li>
 *   <li>Match the remaining 35 hex characters locally without disclosing the complete hash over the network.</li>
 * </ol>
 *
 * <p>Enables {@code Add-Padding: true} to ensure uniform response size across buckets, preventing
 * side-channel prefix inference based on payload length.
 */
@Component
public class PwnedPasswordsClient {

    private static final Logger log = LoggerFactory.getLogger(PwnedPasswordsClient.class);

    /** The protocol splits a 40-char SHA-1 hex digest as 5 + 35. */
    private static final int PREFIX_LENGTH = 5;

    public static final String SOURCE = "PWNED_PASSWORDS_RANGE_API";

    private final BreachProperties.PwnedPasswords config;
    private final long timeoutMs;
    private final RestClient restClient;

    public PwnedPasswordsClient(BreachProperties properties) {
        this.config = properties.pwnedPasswords();
        this.timeoutMs = properties.lookupTimeoutMs();
        this.restClient = RestClient.builder()
                .baseUrl(config.baseUrl())
                .defaultHeader("User-Agent", "TrustShield-BreachMonitor/1.0")
                .build();
    }

    public boolean isEnabled() {
        return config.enabled();
    }

    /**
     * Checks a password against the breach corpus without transmitting it.
     *
     * @param password the candidate. Never logged, never persisted, never sent.
     * @return the lookup outcome; {@code UNAVAILABLE} when disabled or on any failure
     */
    public BreachLookupResult check(String password) {
        if (!config.enabled()) {
            return BreachLookupResult.unavailable(SOURCE,
                    "Range API lookups are disabled; set trustshield.breach.pwned-passwords.enabled=true");
        }
        if (password == null || password.isEmpty()) {
            return BreachLookupResult.unavailable(SOURCE, "Empty password");
        }

        String hash = HashUtils.sha1HexUpper(password);
        String prefix = hash.substring(0, PREFIX_LENGTH);
        String suffix = hash.substring(PREFIX_LENGTH);

        try {
            RestClient.RequestHeadersSpec<?> request = restClient.get()
                    .uri("/range/{prefix}", prefix)
                    .header("Accept", "text/plain");
            if (config.addPadding()) {
                request = request.header("Add-Padding", "true");
            }

            String body = request.retrieve().body(String.class);
            if (body == null || body.isBlank()) {
                return BreachLookupResult.unavailable(SOURCE, "Empty response from range API");
            }

            long count = findSuffix(body, suffix);
            // Only the prefix is ever logged. Logging the full hash would defeat
            // the entire point of the protocol.
            log.debug("Range lookup for prefix {} returned {} lines", prefix, countLines(body));

            return count > 0
                    ? BreachLookupResult.exposed(count, SOURCE)
                    : BreachLookupResult.notFound(SOURCE);

        } catch (Exception e) {
            // Any failure degrades to UNAVAILABLE. It must not be reported as clean.
            log.warn("Pwned Passwords lookup failed for prefix {}: {}", prefix, e.getMessage());
            return BreachLookupResult.unavailable(SOURCE, "Lookup failed: " + e.getClass().getSimpleName());
        }
    }

    /**
     * Scans the {@code SUFFIX:COUNT} response for our suffix.
     *
     * @return the occurrence count, or 0 when absent
     */
    static long findSuffix(String body, String suffix) {
        String target = suffix.toUpperCase(Locale.ROOT);
        for (String line : body.split("\\R")) {
            int colon = line.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            // Full-length match only. A prefix match would collide with other
            // suffixes in the same bucket and report the wrong password.
            if (!line.substring(0, colon).equalsIgnoreCase(target)) {
                continue;
            }
            try {
                long count = Long.parseLong(line.substring(colon + 1).trim());
                // A zero count is a padding entry, not a match. Treating padding
                // as a hit would report every password as breached.
                return Math.max(count, 0L);
            } catch (NumberFormatException e) {
                return 0L;
            }
        }
        return 0L;
    }

    private static int countLines(String body) {
        return body.split("\\R").length;
    }

    /** Exposed for the timeout budget in tests and for documentation. */
    public Duration timeout() {
        return Duration.ofMillis(timeoutMs);
    }
}
