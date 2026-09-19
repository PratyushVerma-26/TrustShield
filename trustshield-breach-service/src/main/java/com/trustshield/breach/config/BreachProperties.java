package com.trustshield.breach.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Externalised configuration for the breach monitor.
 *
 * @param offlineCatalogPath  classpath location of the bundled common-password list
 * @param lookupTimeoutMs     wall-clock budget for any single outbound call
 * @param pwnedPasswords      Pwned Passwords range API settings (k-anonymous)
 * @param hibpAccount         HIBP breached-account settings (NOT k-anonymous)
 */
@ConfigurationProperties(prefix = "trustshield.breach")
public record BreachProperties(
        String offlineCatalogPath,
        long lookupTimeoutMs,
        PwnedPasswords pwnedPasswords,
        HibpAccount hibpAccount
) {

    public BreachProperties {
        offlineCatalogPath = offlineCatalogPath == null
                ? "classpath:breach/common-passwords.txt"
                : offlineCatalogPath;
        lookupTimeoutMs = lookupTimeoutMs <= 0 ? 1500L : lookupTimeoutMs;
        pwnedPasswords = pwnedPasswords == null ? new PwnedPasswords(false, null, true) : pwnedPasswords;
        hibpAccount = hibpAccount == null ? new HibpAccount(false, null, null) : hibpAccount;
    }

    /**
     * Pwned Passwords range API.
     *
     * @param enabled  whether to attempt the network lookup at all. Default false
     *                 so the service is demo-safe with no connectivity; the
     *                 offline catalog still answers.
     * @param baseUrl  API base, overridable so tests can point at a mock server
     * @param addPadding whether to send {@code Add-Padding: true}. The API then
     *                 pads every response to a uniform size, which prevents an
     *                 observer inferring the queried prefix from response length.
     *                 Defaults to true; there is no good reason to disable it.
     */
    public record PwnedPasswords(boolean enabled, String baseUrl, boolean addPadding) {
        public PwnedPasswords {
            baseUrl = (baseUrl == null || baseUrl.isBlank())
                    ? "https://api.pwnedpasswords.com"
                    : baseUrl.replaceAll("/+$", "");
        }
    }

    /**
     * HIBP breached-account API.
     *
     * <p>Kept as a separate record from {@link PwnedPasswords} specifically so
     * that the absence of k-anonymity here cannot be confused with its presence
     * there. This endpoint transmits the full email address and requires a paid
     * key, so it is disabled unless both {@code enabled} is set and a key is
     * present.
     */
    public record HibpAccount(boolean enabled, String apiKey, String baseUrl) {
        public HibpAccount {
            baseUrl = (baseUrl == null || baseUrl.isBlank())
                    ? "https://haveibeenpwned.com/api/v3"
                    : baseUrl.replaceAll("/+$", "");
        }

        /** Enabled *and* actually usable. A key-less "enabled" is not usable. */
        public boolean usable() {
            return enabled && apiKey != null && !apiKey.isBlank();
        }
    }
}
