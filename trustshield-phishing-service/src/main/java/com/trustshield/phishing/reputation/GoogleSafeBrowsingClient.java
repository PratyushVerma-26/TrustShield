package com.trustshield.phishing.reputation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Google Safe Browsing v4 lookup.
 *
 * <p>Uses the JDK's {@link HttpClient} rather than Spring WebClient to keep the
 * dependency surface small and the timeout behaviour explicit.
 *
 * <p>Safe Browsing is high-precision: a match is strong evidence of malice. It is
 * also low-recall, lagging newly registered phishing domains by hours. An empty
 * response therefore means "not on the list", never "safe".
 */
@Component
public class GoogleSafeBrowsingClient implements ReputationSource {

    private static final Logger log = LoggerFactory.getLogger(GoogleSafeBrowsingClient.class);
    private static final String ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find";

    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;

    @Value("${trustshield.phishing.reputation.google-safe-browsing.enabled:false}")
    private boolean enabled;

    @Value("${trustshield.phishing.reputation.google-safe-browsing.api-key:}")
    private String apiKey;

    @Value("${trustshield.phishing.enrichment-timeout-ms:1200}")
    private long timeoutMs;

    public GoogleSafeBrowsingClient(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(800))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    @Override
    public String name() {
        return "GOOGLE_SAFE_BROWSING";
    }

    @Override
    public boolean isEnabled() {
        return enabled && apiKey != null && !apiKey.isBlank();
    }

    @Override
    public ReputationVerdict check(String url) {
        if (!isEnabled()) {
            return ReputationVerdict.unavailable(name(), "No API key configured");
        }
        try {
            String body = objectMapper.writeValueAsString(buildRequest(url));

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(ENDPOINT + "?key=" + apiKey))
                    .timeout(Duration.ofMillis(timeoutMs))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            HttpResponse<String> response =
                    httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 429) {
                return ReputationVerdict.unavailable(name(), "Rate limited");
            }
            if (response.statusCode() != 200) {
                return ReputationVerdict.unavailable(
                        name(), "HTTP " + response.statusCode());
            }

            JsonNode root = objectMapper.readTree(response.body());
            JsonNode matches = root.path("matches");

            // An empty body ({}) means "no match in the list", which is NOT the
            // same as safe. Reported as clean-but-known-low-recall.
            if (!matches.isArray() || matches.isEmpty()) {
                return ReputationVerdict.clean(name(), 0, "No Safe Browsing match");
            }

            String threatType = matches.get(0).path("threatType").asText("UNKNOWN");
            return ReputationVerdict.flagged(name(), 100,
                    "Safe Browsing match: " + threatType);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return ReputationVerdict.unavailable(name(), "Interrupted");
        } catch (Exception e) {
            log.debug("Safe Browsing lookup failed for {}: {}", url, e.toString());
            return ReputationVerdict.unavailable(name(), "Lookup failed: " + e.getClass().getSimpleName());
        }
    }

    private Object buildRequest(String url) {
        return java.util.Map.of(
                "client", java.util.Map.of(
                        "clientId", "trustshield",
                        "clientVersion", "1.0.0"),
                "threatInfo", java.util.Map.of(
                        "threatTypes", java.util.List.of(
                                "MALWARE", "SOCIAL_ENGINEERING",
                                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"),
                        "platformTypes", java.util.List.of("ANY_PLATFORM"),
                        "threatEntryTypes", java.util.List.of("URL"),
                        "threatEntries", java.util.List.of(java.util.Map.of("url", url))));
    }
}
