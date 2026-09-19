package com.trustshield.fakenews.service;

import com.trustshield.common.dto.ClaimCheckRequest;
import com.trustshield.common.dto.ClaimCheckResponse;
import com.trustshield.common.dto.ThreatLevel;
import com.trustshield.fakenews.client.GoogleFactCheckClient;
import com.trustshield.fakenews.entity.ClaimCheckRecord;
import com.trustshield.fakenews.repository.ClaimCheckRecordRepository;
import com.trustshield.fakenews.simhash.DebunkedClaimCatalog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Service orchestrating claim verification, persistence, and aggregate metrics.
 */
@Service
public class ClaimCheckService {

    private static final Logger log = LoggerFactory.getLogger(ClaimCheckService.class);

    private final ClaimVerificationOrchestrator orchestrator;
    private final ClaimCheckRecordRepository repository;
    private final GoogleFactCheckClient factCheckClient;
    private final DebunkedClaimCatalog claimCatalog;

    public ClaimCheckService(
            ClaimVerificationOrchestrator orchestrator,
            ClaimCheckRecordRepository repository,
            GoogleFactCheckClient factCheckClient,
            DebunkedClaimCatalog claimCatalog) {
        this.orchestrator = orchestrator;
        this.repository = repository;
        this.factCheckClient = factCheckClient;
        this.claimCatalog = claimCatalog;
    }

    /**
     * Verifies the claim, records the outcome, and persists an audit entry.
     */
    @Transactional
    public ClaimCheckResponse checkClaim(ClaimCheckRequest request) {
        long startMs = System.currentTimeMillis();
        ClaimCheckResponse response = orchestrator.verifyClaim(request);
        long latencyMs = System.currentTimeMillis() - startMs;

        try {
            ClaimCheckRecord record = new ClaimCheckRecord(
                    response.incidentId() != null ? response.incidentId().value() : null,
                    response.claimText(),
                    request.context(),
                    response.verdict().riskScore(),
                    response.verdict().threatLevel(),
                    response.verdict().verdict(),
                    response.verdict().explanation(),
                    response.verdict().degraded(),
                    response.factCheck() != null && response.factCheck().consulted(),
                    response.factCheck() != null && response.factCheck().matchFound(),
                    response.factCheck() != null ? response.factCheck().publisher() : null,
                    response.simHashMatch() != null && response.simHashMatch().matched(),
                    response.simHashMatch() != null ? response.simHashMatch().similarity() : 0.0,
                    response.styleAnalysis() != null ? response.styleAnalysis().styleRiskScore() : 0,
                    Instant.now(),
                    latencyMs
            );
            repository.save(record);
        } catch (Exception e) {
            log.error("Failed to persist claim check record: {}", e.getMessage(), e);
        }

        return response;
    }

    public List<ClaimCheckRecord> getRecentChecks() {
        return repository.findTop25ByOrderByCheckedAtDesc();
    }

    public MisinformationStats getStats() {
        long total = repository.count();
        Map<ThreatLevel, Long> distribution = new EnumMap<>(ThreatLevel.class);
        for (ThreatLevel level : ThreatLevel.values()) {
            distribution.put(level, repository.countByThreatLevel(level));
        }

        return new MisinformationStats(
                total,
                repository.countBySimHashMatchedTrue(),
                repository.countByFactCheckMatchedTrue(),
                distribution,
                factCheckClient.isEnabled(),
                claimCatalog.getEntryCount()
        );
    }

    public record MisinformationStats(
            long totalChecks,
            long simHashMatches,
            long factCheckMatches,
            Map<ThreatLevel, Long> threatDistribution,
            boolean factCheckApiEnabled,
            int catalogEntryCount
    ) {}
}
