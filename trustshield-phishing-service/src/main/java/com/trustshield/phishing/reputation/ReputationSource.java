package com.trustshield.phishing.reputation;

/**
 * An external URL reputation provider.
 *
 * <p>Implementations must never throw: a failing third-party API must degrade the
 * verdict, not fail the user's request. Return
 * {@link ReputationVerdict#unavailable} instead.
 *
 * <p>On PhishTank: the original project design listed PhishTank as a live API
 * source. PhishTank stopped issuing new developer API keys, so relying on it at
 * runtime is not dependable. It is used here as an offline <em>training data</em>
 * source (see scripts/train_phishing_model.py) rather than a live lookup, which
 * is both more honest and more reliable.
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
