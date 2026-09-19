package com.trustshield.fakenews.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustshield.common.dto.ClaimCheckResponse.FactCheckResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Client for Google Fact Check Tools API (v1alpha1).
 *
 * <p>Direct fact-checking corroboration is primary evidence: a matching claim review by a
 * recognised fact-checker (Alt News, Boom Live, Snopes, PolitiFact, Reuters) is authoritative
 * evidence that the claim has been investigated and rated.
 *
 * <p>Invariants:
 * <ul>
 *   <li>Ships disabled by default; requires an explicit API key.</li>
 *   <li>When disabled or unreachable, returns {@link FactCheckResult#unavailable()} rather than
 *       synthesising a clean result.</li>
 *   <li>When consulted but no claim review is found, returns {@code consulted=true, matchFound=false}.
 *       This signifies "not indexed in fact-checking database", NOT "verified true".</li>
 * </ul>
 */
@Component
public class GoogleFactCheckClient {

    private static final Logger log = LoggerFactory.getLogger(GoogleFactCheckClient.class);

    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;

    @Value("${trustshield.fakenews.fact-check.enabled:false}")
    private boolean enabled;

    @Value("${trustshield.fakenews.fact-check.api-key:}")
    private String apiKey;

    @Value("${trustshield.fakenews.fact-check.base-url:https://factchecktools.googleapis.com/v1alpha1/claims:search}")
    private String baseUrl;

    @Value("${trustshield.fakenews.fact-check.timeout-ms:3000}")
    private long timeoutMs;

    @Value("${trustshield.fakenews.fact-check.language-code:en}")
    private String languageCode;

    @Autowired
    public GoogleFactCheckClient(ObjectMapper objectMapper) {
        this(objectMapper, HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(1500))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build());
    }

    public GoogleFactCheckClient(ObjectMapper objectMapper, HttpClient httpClient) {
        this.objectMapper = objectMapper;
        this.httpClient = httpClient;
    }

    public boolean isEnabled() {
        return enabled && apiKey != null && !apiKey.isBlank();
    }

    /**
     * Queries Google Fact Check Tools API for claims matching the given text.
     *
     * @param claimText the claim statement or query
     * @return FactCheckResult describing whether the API was consulted and whether a review was found
     */
    public FactCheckResult searchClaim(String claimText) {
        if (!isEnabled()) {
            return FactCheckResult.unavailable();
        }

        if (claimText == null || claimText.isBlank()) {
            return FactCheckResult.unavailable();
        }

        try {
            String encodedQuery = URLEncoder.encode(claimText.trim(), StandardCharsets.UTF_8);
            String url = String.format("%s?query=%s&key=%s&languageCode=%s",
                    baseUrl, encodedQuery, apiKey, languageCode);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofMillis(timeoutMs))
                    .header("Accept", "application/json")
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                return parseApiResponse(response.body());
            }

            log.warn("Google Fact Check API returned HTTP status {}: {}", response.statusCode(), response.body());
            return FactCheckResult.unavailable();
        } catch (Exception e) {
            log.warn("Google Fact Check API query failed for '{}': {}", claimText, e.getMessage());
            return FactCheckResult.unavailable();
        }
    }

    private FactCheckResult parseApiResponse(String responseBody) {
        try {
            JsonNode root = objectMapper.readTree(responseBody);
            JsonNode claimsNode = root.path("claims");

            if (!claimsNode.isArray() || claimsNode.isEmpty()) {
                // Consulted, but no matching reviews indexed
                return new FactCheckResult(true, false, null, null, null, null, null);
            }

            JsonNode firstClaim = claimsNode.get(0);
            String claimant = firstClaim.path("claimant").asText(null);

            JsonNode reviews = firstClaim.path("claimReview");
            if (reviews.isArray() && !reviews.isEmpty()) {
                JsonNode firstReview = reviews.get(0);
                String publisher = firstReview.path("publisher").path("name").asText("Fact Checking Agency");
                String reviewTitle = firstReview.path("title").asText(firstClaim.path("text").asText(null));
                String reviewUrl = firstReview.path("url").asText(null);
                String textualRating = firstReview.path("textualRating").asText("False");

                return new FactCheckResult(
                        true,
                        true,
                        claimant,
                        reviewTitle,
                        reviewUrl,
                        textualRating,
                        publisher
                );
            }

            return new FactCheckResult(true, false, claimant, null, null, null, null);
        } catch (Exception e) {
            log.warn("Failed to parse Google Fact Check API response: {}", e.getMessage());
            return FactCheckResult.unavailable();
        }
    }

    // Setters for testability
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }
}
