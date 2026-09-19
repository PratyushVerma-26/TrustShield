package com.trustshield.breach.hibp;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.trustshield.breach.config.BreachProperties;

/**
 * Client for the HIBP breached-account endpoint.
 *
 * <p><strong>This endpoint is not k-anonymous, and the class is separate from
 * {@link PwnedPasswordsClient} to make that impossible to overlook.</strong> It
 * transmits the full email address to a third party and requires a paid API key.
 * There is no prefix trick available: HIBP does not offer a range variant for
 * accounts, because the answer set is per-address rather than per-hash-bucket.
 *
 * <p>Consequences that follow from that, and which are implemented here:
 *
 * <ul>
 *   <li>Disabled by default. A demo must not silently exfiltrate an address.</li>
 *   <li>The API response is reduced to breach <em>names and metadata returned by
 *       HIBP itself</em>. Nothing is inferred or embellished locally.</li>
 *   <li>The caller is told {@code kAnonymous=false} so the UI can warn before the
 *       lookup, which is the DPDP Act's notice-and-consent expectation rather
 *       than an afterthought.</li>
 * </ul>
 *
 * <p>When no key is configured the service returns {@code UNAVAILABLE} and the
 * verdict is marked degraded. It does not fall back to guessing.
 */
@Component
public class HibpAccountClient {

    private static final Logger log = LoggerFactory.getLogger(HibpAccountClient.class);

    public static final String SOURCE = "HIBP_BREACHED_ACCOUNT";

    private final BreachProperties.HibpAccount config;
    private final RestClient restClient;

    public HibpAccountClient(BreachProperties properties) {
        this.config = properties.hibpAccount();
        this.restClient = RestClient.builder()
                .baseUrl(config.baseUrl())
                .defaultHeader("User-Agent", "TrustShield-BreachMonitor/1.0 (academic project)")
                .build();
    }

    /** True only when enabled *and* a key is present. */
    public boolean isUsable() {
        return config.usable();
    }

    /**
     * Looks up breaches for an email address.
     *
     * @return the breaches HIBP reported, or an unavailable result. Never a
     *         fabricated or partial list presented as complete.
     */
    public AccountLookup lookup(String email) {
        if (!config.usable()) {
            return new AccountLookup(
                    BreachLookupResult.unavailable(SOURCE,
                            "Email breach lookup needs a HIBP API key. It is disabled by default because, "
                                    + "unlike the password check, it transmits the full address."),
                    List.of());
        }

        try {
            HibpBreach[] breaches = restClient.get()
                    .uri("/breachedaccount/{account}?truncateResponse=false", email)
                    .header("hibp-api-key", config.apiKey())
                    .header("Accept", "application/json")
                    .retrieve()
                    .body(HibpBreach[].class);

            if (breaches == null || breaches.length == 0) {
                return new AccountLookup(BreachLookupResult.notFound(SOURCE), List.of());
            }
            return new AccountLookup(
                    BreachLookupResult.exposed(breaches.length, SOURCE),
                    List.of(breaches));

        } catch (Exception e) {
            // HIBP returns 404 for "not found", which RestClient raises as an
            // exception. Distinguish it, because 404 here is a real answer.
            String msg = e.getMessage() == null ? "" : e.getMessage();
            if (msg.contains("404")) {
                return new AccountLookup(BreachLookupResult.notFound(SOURCE), List.of());
            }
            log.warn("HIBP account lookup failed: {}", e.getClass().getSimpleName());
            return new AccountLookup(
                    BreachLookupResult.unavailable(SOURCE, "Lookup failed: " + e.getClass().getSimpleName()),
                    List.of());
        }
    }

    /**
     * A breach as described by HIBP.
     *
     * <p>HIBP returns PascalCase JSON. Rather than naming the record components
     * {@code Name}/{@code Title} to match — which is legal Java but reads like a
     * mistake — the mapping is made explicit with {@code @JsonProperty}.
     *
     * <p>Only the subset of fields actually shown to the user is mapped; Jackson
     * ignores the rest by default.
     */
    public record HibpBreach(
            @JsonProperty("Name") String name,
            @JsonProperty("Title") String title,
            @JsonProperty("Domain") String domain,
            @JsonProperty("BreachDate") String breachDate,
            @JsonProperty("PwnCount") Integer pwnCount,
            @JsonProperty("DataClasses") List<String> dataClasses,
            @JsonProperty("IsVerified") Boolean verified,
            @JsonProperty("IsSensitive") Boolean sensitive
    ) {
    }

    /** Lookup outcome plus the breach detail, when there is any. */
    public record AccountLookup(BreachLookupResult result, List<HibpBreach> breaches) {
    }
}
