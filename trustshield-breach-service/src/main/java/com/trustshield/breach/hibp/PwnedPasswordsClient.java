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
 * Client for the Pwned Passwords range API, implementing k-anonymity properly.
 *
 * <h2>The protocol, and why each step matters</h2>
 *
 * <ol>
 *   <li>SHA-1 the candidate password locally and upper-case the hex. SHA-1 is
 *       used because the protocol mandates it, not because it was chosen as a
 *       secure hash — see {@link HashUtils#sha1HexUpper}.</li>
 *   <li>Send only the <strong>first five hex characters</strong> as a path
 *       segment: {@code GET /range/21BD1}.</li>
 *   <li>The server returns every suffix in that bucket with its occurrence
 *       count — typically several hundred lines.</li>
 *   <li>Match the remaining <strong>35 characters</strong> locally.</li>
 * </ol>
 *
 * <p>The server therefore learns a 5-hex-character prefix, which is one bucket
 * out of 16^5 = 1,048,576. It never receives the password and never receives the
 * full hash, so it cannot determine which password was queried. That is the
 * k-anonymity property, and it is a property of <em>this</em> endpoint only.
 *
 * <p><strong>The mistake this class exists to avoid.</strong> The original
 * project draft described checking <em>email addresses</em> "using HIBP
 * k-anonymity". There is no such thing: the breached-account endpoint takes the
 * full address. See {@link HibpAccountClient}, which is deliberately a separate
 * class so the two cannot be conflated.
 *
 * <h2>Padding</h2>
 *
 * <p>{@code Add-Padding: true} makes the API return a uniform number of lines
 * regardless of bucket, padded with entries whose count is zero. Without it, an
 * observer who can see response sizes can narrow down the queried prefix. Zero
 * counts are filtered out during parsing, which is required — a padding entry
 * must never be read as a real match.
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
                .defaultHeader("User-Agent", "TrustShield-BreachMonitor/1.0 (academic project)")
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
