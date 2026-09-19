package com.trustshield.breach.hibp;

import java.util.Optional;

/**
 * Outcome of a credential breach lookup.
 *
 * <p>Represents lookup outcomes using a three-state model (EXPOSED, NOT_FOUND,
 * UNAVAILABLE) to differentiate between verified negative findings and network
 * or lookup failures.
 *
 * @param status         outcome status
 * @param occurrences    frequency of the secret in the corpus, when reported by the source
 * @param source         identifier of the reporting source
 * @param detail         human-readable explanation of the outcome
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
        /** The lookup could not be completed (e.g. network timeout or service disabled). */
        UNAVAILABLE
    }

    public static BreachLookupResult exposed(long occurrences, String source) {
        return new BreachLookupResult(Status.EXPOSED, Optional.of(occurrences), source,
                "Found in breach corpus");
    }

    /**
     * Found, but the source reports set membership only without frequency counts.
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
