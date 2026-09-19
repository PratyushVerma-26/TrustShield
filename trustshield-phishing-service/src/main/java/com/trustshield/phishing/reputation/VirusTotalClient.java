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
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

/**
 * VirusTotal v3 URL reputation lookup.
 *
 * <p>Two behaviours worth noting, both of which the original project draft got
 * wrong:
 *
 * <ol>
 *   <li>VirusTotal identifies a URL by its unpadded base64url encoding. Using
 *       standard base64 (with {@code +}, {@code /} and {@code =}) yields a
 *       malformed identifier and a 400.</li>
 *   <li>A URL VirusTotal has never analysed returns <strong>404</strong>, not a
 *       clean result. Treating 404 as clean — as a naive implementation does —
 *       means every freshly registered phishing domain, which is exactly the
 *       dangerous case, is reported as safe. Here 404 maps to
 *       {@code unavailable}.</li>
 * </ol>
 *
 * <p>Submitting unknown URLs for analysis and polling for the result is possible
 * but takes tens of seconds, far outside the latency budget, so it is not done
 * on the request path.
 */
@Component
public class VirusTotalClient implements ReputationSource {

    private static final Logger log = LoggerFactory.getLogger(VirusTotalClient.class);
    private static final String ENDPOINT = "https://www.virustotal.com/api/v3/urls/";

    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;

    @Value("${trustshield.phishing.reputation.virustotal.enabled:false}")
    private boolean enabled;

    @Value("${trustshield.phishing.reputation.virustotal.api-key:}")
    private String apiKey;

    @Value("${trustshield.phishing.enrichment-timeout-ms:1200}")
    private long timeoutMs;

    public VirusTotalClient(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(800))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    @Override
    public String name() {
        return "VIRUSTOTAL";
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
            String urlId = Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(url.getBytes(StandardCharsets.UTF_8));

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(ENDPOINT + urlId))
                    .timeout(Duration.ofMillis(timeoutMs))
                    .header("x-apikey", apiKey)
                    .header("Accept", "application/json")
                    .GET()
                    .build();

            HttpResponse<String> response =
                    httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            int status = response.statusCode();
            if (status == 404) {
                // Never analysed. Explicitly NOT clean.
                return ReputationVerdict.unavailable(name(), "URL not yet analysed by VirusTotal");
            }
            if (status == 429) {
                return ReputationVerdict.unavailable(name(), "Rate limited (free tier is 4 req/min)");
            }
            if (status == 401) {
                return ReputationVerdict.unavailable(name(), "API key rejected");
            }
            if (status != 200) {
                return ReputationVerdict.unavailable(name(), "HTTP " + status);
            }

            JsonNode stats = objectMapper.readTree(response.body())
                    .path("data").path("attributes").path("last_analysis_stats");

            int malicious = stats.path("malicious").asInt(0);
            int suspicious = stats.path("suspicious").asInt(0);
            int harmless = stats.path("harmless").asInt(0);
            int undetected = stats.path("undetected").asInt(0);
            int total = malicious + suspicious + harmless + undetected;

            if (total == 0) {
                return ReputationVerdict.unavailable(name(), "No engine results present");
            }

            int score = (int) Math.round(((malicious + suspicious) / (double) total) * 100);
            String detail = malicious + "/" + total + " engines flagged this URL";

            // Two or more independent engines is the threshold for treating this
            // as a positive. A single engine flagging is frequently a false
            // positive on VirusTotal and is recorded as a score without being
            // treated as confirmation.
            return (malicious >= 2)
                    ? ReputationVerdict.flagged(name(), score, detail)
                    : ReputationVerdict.clean(name(), score, detail);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return ReputationVerdict.unavailable(name(), "Interrupted");
        } catch (Exception e) {
            log.debug("VirusTotal lookup failed for {}: {}", url, e.toString());
            return ReputationVerdict.unavailable(name(), "Lookup failed: " + e.getClass().getSimpleName());
        }
    }
}
