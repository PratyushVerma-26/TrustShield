package com.trustshield.fusion.service;

import com.trustshield.common.dto.FusionRuleResult;
import com.trustshield.common.dto.IncidentFusionRequest;
import com.trustshield.common.dto.IncidentFusionResponse;
import com.trustshield.common.dto.ThreatLevel;
import com.trustshield.fusion.engine.FusionRule;
import com.trustshield.fusion.engine.ThreatFusionEngine;
import com.trustshield.fusion.entity.IncidentFusionRecord;
import com.trustshield.fusion.repository.IncidentFusionRecordRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Service orchestrating cross-modal incident risk fusion, persistence, and statistics.
 */
@Service
public class IncidentFusionService {

    private static final Logger log = LoggerFactory.getLogger(IncidentFusionService.class);

    private final ThreatFusionEngine engine;
    private final IncidentFusionRecordRepository repository;

    public IncidentFusionService(ThreatFusionEngine engine, IncidentFusionRecordRepository repository) {
        this.engine = engine;
        this.repository = repository;
    }

    /**
     * Executes cross-modal fusion evaluation and persists audit history.
     */
    @Transactional
    public IncidentFusionResponse evaluateIncident(IncidentFusionRequest request) {
        long startMs = System.currentTimeMillis();
        IncidentFusionResponse response = engine.fuseIncident(request);
        long latencyMs = System.currentTimeMillis() - startMs;

        try {
            int firedCount = (int) response.firedRules().stream().filter(FusionRuleResult::fired).count();
            IncidentFusionRecord record = new IncidentFusionRecord(
                    response.incidentId().value(),
                    response.aggregateVerdict().riskScore(),
                    response.aggregateVerdict().threatLevel(),
                    response.aggregateVerdict().verdict(),
                    response.aggregateVerdict().explanation(),
                    firedCount,
                    response.contributions().size(),
                    response.ledgerVerified(),
                    response.safeDisallowedByUnknown(),
                    Instant.now(),
                    latencyMs
            );
            repository.save(record);
        } catch (Exception e) {
            log.error("Failed to persist incident fusion record: {}", e.getMessage(), e);
        }

        return response;
    }

    public List<IncidentFusionRecord> getRecentIncidents() {
        return repository.findTop25ByOrderByEvaluatedAtDesc();
    }

    public List<FusionRule> getActiveRules() {
        return engine.getRules();
    }

    public FusionStats getStats() {
        long total = repository.count();
        Map<ThreatLevel, Long> distribution = new EnumMap<>(ThreatLevel.class);
        for (ThreatLevel level : ThreatLevel.values()) {
            distribution.put(level, repository.countByThreatLevel(level));
        }

        return new FusionStats(
                total,
                repository.countByLedgerVerifiedFalse(),
                repository.countBySafeDisallowedTrue(),
                distribution,
                engine.getRules().size()
        );
    }

    public record FusionStats(
            long totalIncidentsEvaluated,
            long ledgerTamperOverrides,
            long safeDisallowedDueToUnknown,
            Map<ThreatLevel, Long> threatDistribution,
            int activeRulesCount
    ) {}
}
