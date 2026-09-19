package com.trustshield.phishing.reputation;

/**
 * Contract for external URL reputation providers.
 *
 * <p>Implementations query reputation data within the caller's timeout budget
 * and return {@link ReputationVerdict#unavailable} on upstream network failure
 * rather than throwing unhandled exceptions.
 */
public interface ReputationSource {

    /** Stable identifier used in signals and logs. */
    String name();

    /** False when no API key is configured or the source is switched off. */
    boolean isEnabled();

    /**
     * Consults the source. Must return within the caller's timeout budget and
     * must not throw.
     */
    ReputationVerdict check(String url);
}
