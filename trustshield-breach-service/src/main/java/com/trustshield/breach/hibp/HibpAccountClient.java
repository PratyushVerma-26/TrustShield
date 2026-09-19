package com.trustshield.breach.hibp;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.trustshield.breach.config.BreachProperties;

/**
 * Client for the Have I Been Pwned (HIBP) breached-account endpoint.
 *
 * <p>Unlike range-based password queries, account breach checks transmit
 * the query email address to the external API and require a configured API key.
 *
 * <p>Key operational characteristics:
 * <ul>
 *   <li>Disabled by default; requires explicit enablement and API key configuration.</li>
 *   <li>Parses breach metadata returned by the upstream provider without local inference.</li>
 *   <li>Reports {@code kAnonymous=false} to provide transparent privacy posture to clients.</li>
 * </ul>
 *
 * <p>When no key is configured, the client returns an {@code UNAVAILABLE} result
 * with degraded status.
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
                .defaultHeader("User-Agent", "TrustShield-BreachMonitor/1.0")
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
     * A breach record returned by HIBP.
     *
     * <p>Maps upstream PascalCase JSON properties explicitly to canonical Java record fields.
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
