package com.trustshield.bot.router;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.trustshield.common.dto.ClaimCheckRequest;
import com.trustshield.common.dto.ClaimCheckResponse;
import com.trustshield.common.dto.DeepfakeScanRequest;
import com.trustshield.common.dto.DeepfakeScanResponse;
import com.trustshield.common.dto.IncidentFusionRequest;
import com.trustshield.common.dto.IncidentFusionResponse;
import com.trustshield.common.dto.IncidentId;
import com.trustshield.common.dto.LedgerAppendRequest;
import com.trustshield.common.dto.ModuleType;
import com.trustshield.common.dto.ModuleVerdict;
import com.trustshield.common.dto.ThreatLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Dispatches conversational security queries to TrustShield microservices with resilient offline fallbacks.
 */
@Component
public class MicroserviceRouter {

    private static final Logger log = LoggerFactory.getLogger(MicroserviceRouter.class);

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record PhishingScanResponseDto(
            Long scanId,
            String url,
            ModuleVerdict verdict
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record PasswordCheckResponseDto(
            ModuleVerdict verdict,
            String recommendation
    ) {}

    private final RestClient restClient;
    private final String phishingUrl;
    private final String breachUrl;
    private final String deepfakeUrl;
    private final String fakenewsUrl;
    private final String integrityUrl;
    private final String fusionUrl;

    @Autowired
    public MicroserviceRouter(
            @Value("${trustshield.services.phishing-url:http://localhost:8083}") String phishingUrl,
            @Value("${trustshield.services.breach-url:http://localhost:8084}") String breachUrl,
            @Value("${trustshield.services.deepfake-url:http://localhost:8085}") String deepfakeUrl,
            @Value("${trustshield.services.fakenews-url:http://localhost:8086}") String fakenewsUrl,
            @Value("${trustshield.services.integrity-url:http://localhost:8087}") String integrityUrl,
            @Value("${trustshield.services.fusion-url:http://localhost:8088}") String fusionUrl,
            @Value("${trustshield.bot.default-timeout-ms:4000}") int timeoutMs) {

        this(createDefaultRestClient(timeoutMs), phishingUrl, breachUrl, deepfakeUrl, fakenewsUrl, integrityUrl, fusionUrl);
    }

    public MicroserviceRouter(
            RestClient restClient,
            String phishingUrl,
            String breachUrl,
            String deepfakeUrl,
            String fakenewsUrl,
            String integrityUrl,
            String fusionUrl) {
        this.restClient = restClient;
        this.phishingUrl = phishingUrl != null ? phishingUrl.replaceAll("/+$", "") : "http://localhost:8083";
        this.breachUrl = breachUrl != null ? breachUrl.replaceAll("/+$", "") : "http://localhost:8084";
        this.deepfakeUrl = deepfakeUrl != null ? deepfakeUrl.replaceAll("/+$", "") : "http://localhost:8085";
        this.fakenewsUrl = fakenewsUrl != null ? fakenewsUrl.replaceAll("/+$", "") : "http://localhost:8086";
        this.integrityUrl = integrityUrl != null ? integrityUrl.replaceAll("/+$", "") : "http://localhost:8087";
        this.fusionUrl = fusionUrl != null ? fusionUrl.replaceAll("/+$", "") : "http://localhost:8088";
    }

    private static RestClient createDefaultRestClient(int timeoutMs) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout((int) Duration.ofMillis(timeoutMs).toMillis());
        factory.setReadTimeout((int) Duration.ofMillis(timeoutMs).toMillis());
        return RestClient.builder().requestFactory(factory).build();
    }

    /**
     * Dispatches a URL scan to the Phishing Service (:8083).
     */
    public ModuleVerdict scanUrl(String url, IncidentId incidentId) {
        try {
            Map<String, String> body = Map.of("url", url, "context", "BOT_SCAN");
            PhishingScanResponseDto response = restClient.post()
                    .uri(phishingUrl + "/api/v1/phishing/scan")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(body)
                    .retrieve()
                    .body(PhishingScanResponseDto.class);

            if (response != null && response.verdict() != null) {
                return response.verdict();
            }
        } catch (Exception e) {
            log.warn("Phishing service call failed for URL {}: {}", url, e.getMessage());
        }

        return ModuleVerdict.inconclusive(
                ModuleType.PHISHING,
                "SCAN_OFFLINE",
                "Phishing scanner unavailable; link remains unverified.",
                List.of(),
                0L
        );
    }

    /**
     * Dispatches a news claim or text forward to the Fake News Service (:8086).
     */
    public ModuleVerdict checkClaim(String claimText, String mediaBase64, String mediaType, IncidentId incidentId) {
        try {
            ClaimCheckRequest request = new ClaimCheckRequest(
                    incidentId,
                    claimText,
                    "BOT_CHAT",
                    mediaType,
                    mediaBase64,
                    null,
                    null
            );

            ClaimCheckResponse response = restClient.post()
                    .uri(fakenewsUrl + "/api/v1/fakenews/check")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(request)
                    .retrieve()
                    .body(ClaimCheckResponse.class);

            if (response != null && response.verdict() != null) {
                return response.verdict();
            }
        } catch (Exception e) {
            log.warn("Fake news service call failed for claim: {}", e.getMessage());
        }

        return ModuleVerdict.inconclusive(
                ModuleType.FAKENEWS,
                "CLAIM_CHECK_OFFLINE",
                "Fact-checking directory service unavailable; claim remains unverified.",
                List.of(),
                0L
        );
    }

    /**
     * Dispatches image, audio, or video forensics to the Deepfake Service (:8085).
     */
    public ModuleVerdict scanMedia(String mediaBase64, String mediaType, String filename, IncidentId incidentId) {
        try {
            DeepfakeScanRequest request = new DeepfakeScanRequest(
                    incidentId,
                    mediaBase64,
                    filename,
                    null,
                    "BOT_CHAT",
                    mediaType
            );

            DeepfakeScanResponse response = restClient.post()
                    .uri(deepfakeUrl + "/api/v1/deepfake/scan")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(request)
                    .retrieve()
                    .body(DeepfakeScanResponse.class);

            if (response != null && response.verdict() != null) {
                return response.verdict();
            }
        } catch (Exception e) {
            log.warn("Deepfake service call failed: {}", e.getMessage());
        }

        return ModuleVerdict.inconclusive(
                ModuleType.DEEPFAKE,
                "MEDIA_SCAN_OFFLINE",
                "Deepfake forensic service unavailable; media integrity unverified.",
                List.of(),
                0L
        );
    }

    /**
     * Dispatches a password k-anonymity breach query to the Breach Service (:8084).
     */
    public ModuleVerdict checkPassword(String password, IncidentId incidentId) {
        try {
            Map<String, String> body = Map.of("password", password);
            PasswordCheckResponseDto response = restClient.post()
                    .uri(breachUrl + "/api/v1/breach/password")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(body)
                    .retrieve()
                    .body(PasswordCheckResponseDto.class);

            if (response != null && response.verdict() != null) {
                return response.verdict();
            }
        } catch (Exception e) {
            log.warn("Breach service call failed: {}", e.getMessage());
        }

        return ModuleVerdict.inconclusive(
                ModuleType.BREACH,
                "BREACH_CHECK_OFFLINE",
                "Breach exposure service unavailable; password status unverified.",
                List.of(),
                0L
        );
    }

    /**
     * Dispatches multi-vector verdicts to the Cross-Modal Threat Fusion Service (:8088).
     */
    public IncidentFusionResponse evaluateFusion(List<ModuleVerdict> verdicts, IncidentId incidentId) {
        try {
            IncidentFusionRequest request = new IncidentFusionRequest(incidentId, verdicts, true);
            IncidentFusionResponse response = restClient.post()
                    .uri(fusionUrl + "/api/v1/fusion/evaluate")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(request)
                    .retrieve()
                    .body(IncidentFusionResponse.class);

            if (response != null) {
                return response;
            }
        } catch (Exception e) {
            log.warn("Fusion service call failed: {}", e.getMessage());
        }

        // Local fallback synthesis if fusion service is offline
        int maxRisk = verdicts.stream().mapToInt(ModuleVerdict::riskScore).max().orElse(0);
        ThreatLevel level = ThreatLevel.fromScore(maxRisk);
        ModuleVerdict aggregate = ModuleVerdict.degraded(
                ModuleType.FUSION,
                maxRisk,
                level.name(),
                "Cross-modal fusion synthesized via local fallback heuristic.",
                List.of(),
                0L
        );
        return new IncidentFusionResponse(incidentId, aggregate, List.of(), Map.of(), Map.of(), true, false);
    }

    /**
     * Appends an audit entry to the Cryptographic Integrity Ledger (:8087).
     */
    public void appendAuditLedger(IncidentId incidentId, ModuleType module, String canonicalVerdictJson) {
        try {
            LedgerAppendRequest request = new LedgerAppendRequest(
                    incidentId,
                    module != null ? module : ModuleType.FUSION,
                    canonicalVerdictJson != null ? canonicalVerdictJson : "{}"
            );
            restClient.post()
                    .uri(integrityUrl + "/api/v1/integrity/append")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(request)
                    .retrieve()
                    .toBodilessEntity();
        } catch (Exception e) {
            log.debug("Integrity ledger append non-blocking error: {}", e.getMessage());
        }
    }

    public String getPhishingUrl() {
        return phishingUrl;
    }

    public String getBreachUrl() {
        return breachUrl;
    }

    public String getDeepfakeUrl() {
        return deepfakeUrl;
    }

    public String getFakenewsUrl() {
        return fakenewsUrl;
    }

    public String getIntegrityUrl() {
        return integrityUrl;
    }

    public String getFusionUrl() {
        return fusionUrl;
    }
}
