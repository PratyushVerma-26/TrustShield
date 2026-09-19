package com.trustshield.breach.hibp;

import java.util.Optional;

/**
 * Outcome of a breach-corpus lookup.
 *
 * <p>Three states, not two — the same reasoning as {@code ReputationVerdict} in
 * the phishing service. Collapsing "the lookup failed" into "the password is
 * clean" is a one-character bug with a direct security consequence: it would
 * tell a user their breached password is safe because a network call timed out.
 *
 * @param status         what actually happened
 * @param occurrences    how many times the secret appears in the corpus, when the
 *                       source reports a count. Empty when the source only
 *                       reports membership (the offline catalog) or when the
 *                       lookup did not succeed.
 * @param source         which source answered, for attribution in the UI
 * @param detail         human-readable note, used mainly for failure reasons
 */
public record BreachLookupResult(
        Status status,
        Optional<Long> occurrences,
        String source,
        String detail
) {

    public enum Status {
        /** The secret was found in the corpus. */
        EXPOSED,
        /** The lookup completed and the secret was not present. */
        NOT_FOUND,
        /** The lookup could not be completed. Absence of evidence, not evidence of absence. */
        UNAVAILABLE
    }

    public static BreachLookupResult exposed(long occurrences, String source) {
        return new BreachLookupResult(Status.EXPOSED, Optional.of(occurrences), source,
                "Found in breach corpus");
    }

    /**
     * Found, but the source does not report a count.
     *
     * <p>Used by the offline catalog. It must not invent a number: reporting
     * "appears 3,000,000 times" from a source that only knows membership would
     * be a fabricated statistic.
     */
    public static BreachLookupResult exposedCountUnknown(String source) {
        return new BreachLookupResult(Status.EXPOSED, Optional.empty(), source,
                "Present in the bundled common-password list; this source does not report counts");
    }

    public static BreachLookupResult notFound(String source) {
        return new BreachLookupResult(Status.NOT_FOUND, Optional.empty(), source,
                "Not present in the consulted corpus");
    }

    public static BreachLookupResult unavailable(String source, String reason) {
        return new BreachLookupResult(Status.UNAVAILABLE, Optional.empty(), source, reason);
    }

    public boolean isExposed() {
        return status == Status.EXPOSED;
    }

    public boolean isUnavailable() {
        return status == Status.UNAVAILABLE;
    }
}
