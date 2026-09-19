package com.trustshield.fusion.engine;

import com.trustshield.common.dto.FusionRuleResult;
import com.trustshield.common.dto.IncidentFusionRequest;
import com.trustshield.common.dto.IncidentFusionResponse;
import com.trustshield.common.dto.ModuleType;
import com.trustshield.common.dto.ModuleVerdict;
import com.trustshield.common.dto.ThreatLevel;
import com.trustshield.common.dto.ThreatSignal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Cross-modal Threat Fusion Engine.
 *
 * <p>Correlates multi-vector incident indicators across phishing, breach, deepfake, fake news,
 * and the cryptographic integrity ledger using deterministic, auditable rules (R1-R5).
 */
@Component
public class ThreatFusionEngine {

    private static final Logger log = LoggerFactory.getLogger(ThreatFusionEngine.class);

    private final List<FusionRule> rules;
    private final int coordinationCompoundBonus;
    private final int ledgerTamperScore;

    public ThreatFusionEngine(
            List<FusionRule> rules,
            @Value("${trustshield.fusion.coordination-compound-bonus:15}") int coordinationCompoundBonus,
            @Value("${trustshield.fusion.ledger-tamper-override-score:95}") int ledgerTamperScore) {
        this.rules = rules;
        this.coordinationCompoundBonus = coordinationCompoundBonus;
        this.ledgerTamperScore = ledgerTamperScore;
    }

    /**
     * Executes cross-modal fusion evaluation over an incident request.
     */
    public IncidentFusionResponse fuseIncident(IncidentFusionRequest request) {
        long startMs = System.currentTimeMillis();

        // 1. Organize modular contributions (deduplicating by keeping higher risk score)
        Map<ModuleType, ModuleVerdict> contributions = new LinkedHashMap<>();
        if (request.verdicts() != null) {
            for (ModuleVerdict v : request.verdicts()) {
                if (v == null || v.module() == null) continue;
                contributions.merge(v.module(), v, (existing, incoming) ->
                        incoming.riskScore() > existing.riskScore() ? incoming : existing);
            }
        }

        // 2. Build coverage map for primary security modalities
        Map<ModuleType, Boolean> coverageMap = new EnumMap<>(ModuleType.class);
        for (ModuleType type : List.of(ModuleType.PHISHING, ModuleType.BREACH, ModuleType.DEEPFAKE, ModuleType.FAKENEWS)) {
            ModuleVerdict v = contributions.get(type);
            boolean covered = v != null && v.threatLevel() != ThreatLevel.UNKNOWN && !v.degraded();
            coverageMap.put(type, covered);
        }

        // 3. Evaluate named, auditable fusion rules (R1 - R5)
        List<FusionRuleResult> ruleResults = new ArrayList<>();
        Map<String, FusionRuleResult> resultMap = new LinkedHashMap<>();
        for (FusionRule rule : rules) {
            FusionRuleResult result = rule.evaluate(request, contributions);
            ruleResults.add(result);
            resultMap.put(result.ruleId(), result);
        }

        // 4. Synthesize aggregate verdict enforcing canonical invariants
        boolean safeDisallowedByUnknown = false;
        ThreatLevel aggregateThreatLevel;
        int aggregateRiskScore;
        String verdictTitle;
        String explanation;

        FusionRuleResult r1 = resultMap.get("R1");
        FusionRuleResult r2 = resultMap.get("R2");
        FusionRuleResult r3 = resultMap.get("R3");
        FusionRuleResult r4 = resultMap.get("R4");
        FusionRuleResult r5 = resultMap.get("R5");

        // Collect all constituent signals
        List<ThreatSignal> aggregatedSignals = new ArrayList<>();
        for (ModuleVerdict v : contributions.values()) {
            if (v.signals() != null) {
                aggregatedSignals.addAll(v.signals());
            }
        }

        // INVARIANT R4: Cryptographic Ledger Override (Integrity breach overrides everything)
        if (r4 != null && r4.fired()) {
            aggregateThreatLevel = ThreatLevel.DANGEROUS;
            aggregateRiskScore = ledgerTamperScore;
            verdictTitle = "INCIDENT_INTEGRITY_TAMPERING";
            explanation = "Cryptographic integrity ledger verification failed. Incident records exhibit evidence of database tampering or SHA-256 chain invalidation.";
            aggregatedSignals.add(ThreatSignal.triggered(
                    "LEDGER_TAMPERING_DETECTED",
                    "SHA-256 hash chain verification or digital signature check failed",
                    ledgerTamperScore,
                    "INTEGRITY_LEDGER"
            ));
        }
        // INVARIANT R1: Conclusive Dangerous Escalation
        else if (r1 != null && r1.fired()) {
            aggregateThreatLevel = ThreatLevel.DANGEROUS;
            int maxDangerousScore = contributions.values().stream()
                    .filter(v -> v.threatLevel() == ThreatLevel.DANGEROUS)
                    .mapToInt(ModuleVerdict::riskScore)
                    .max()
                    .orElse(85);
            aggregateRiskScore = Math.max(85, maxDangerousScore);
            verdictTitle = "CONCLUSIVE_DANGEROUS_ESCALATION";

            String dangerousModules = contributions.entrySet().stream()
                    .filter(e -> e.getValue().threatLevel() == ThreatLevel.DANGEROUS)
                    .map(e -> e.getKey().name())
                    .collect(Collectors.joining(", "));

            explanation = String.format("Conclusive DANGEROUS threat detected in module(s): [%s]. Escalated under rule R1.", dangerousModules);
        }
        // INVARIANT R2: Multi-Modal Suspicious Escalation
        else if (r2 != null && r2.fired()) {
            aggregateThreatLevel = ThreatLevel.DANGEROUS;
            int maxScore = contributions.values().stream().mapToInt(ModuleVerdict::riskScore).max().orElse(50);
            aggregateRiskScore = Math.max(78, Math.min(92, maxScore + 15));
            verdictTitle = "MULTIMODAL_SUSPICIOUS_ESCALATION";

            String suspiciousModules = contributions.entrySet().stream()
                    .filter(e -> e.getValue().threatLevel() == ThreatLevel.SUSPICIOUS)
                    .map(e -> e.getKey().name())
                    .collect(Collectors.joining(", "));

            explanation = String.format("Multiple distinct modalities exhibit SUSPICIOUS indicators [%s]. Coordinated threat escalated to DANGEROUS under rule R2.", suspiciousModules);
        }
        // INVARIANT R5: Cross-Modal Synergistic Attack Multiplier (Phishing + Deepfake/FakeNews)
        else if (r5 != null && r5.fired()) {
            int baseScore = contributions.values().stream().mapToInt(ModuleVerdict::riskScore).max().orElse(45);
            aggregateRiskScore = Math.max(75, Math.min(95, baseScore + coordinationCompoundBonus));
            aggregateThreatLevel = ThreatLevel.fromScore(aggregateRiskScore);
            verdictTitle = "CROSS_MODAL_COORDINATION_ALERT";
            explanation = "Synergistic attack vector detected: social engineering lure (PHISHING) combined with deceptive media/claims. Multiplier applied under rule R5.";
        }
        // BASELINE EVALUATION (No escalation rules fired)
        else if (contributions.isEmpty()) {
            aggregateThreatLevel = ThreatLevel.UNKNOWN;
            aggregateRiskScore = 0;
            verdictTitle = "NO_MODALITIES_EVALUATED";
            explanation = "No modular threat signals were submitted for cross-modal evaluation.";
        }
        else {
            int maxScore = contributions.values().stream().mapToInt(ModuleVerdict::riskScore).max().orElse(0);
            ThreatLevel candidateLevel = ThreatLevel.fromScore(maxScore);

            // INVARIANT R3: Coverage Rule (Refusal to Certify Safe)
            if (r3 != null && r3.fired()) {
                if (candidateLevel == ThreatLevel.SAFE) {
                    safeDisallowedByUnknown = true;
                    aggregateThreatLevel = ThreatLevel.UNKNOWN;
                    aggregateRiskScore = Math.max(0, maxScore);
                    verdictTitle = "INCONCLUSIVE_COVERAGE";
                    explanation = "Cannot certify incident as SAFE because unmeasured or degraded modalities exist. Enforcing coverage rule R3.";
                } else {
                    aggregateThreatLevel = candidateLevel;
                    aggregateRiskScore = maxScore;
                    verdictTitle = "MODULAR_COMPOSITE_VERDICT";
                    explanation = "Composite threat evaluated across available modalities with degraded/unknown coverage.";
                }
            } else {
                aggregateThreatLevel = candidateLevel;
                aggregateRiskScore = maxScore;
                verdictTitle = "MODULAR_COMPOSITE_VERDICT";
                explanation = "All evaluated modalities conclusively reviewed with no detected multi-vector anomalies.";
            }
        }

        long latencyMs = System.currentTimeMillis() - startMs;

        ModuleVerdict aggregateVerdict = new ModuleVerdict(
                ModuleType.FUSION,
                aggregateRiskScore,
                aggregateThreatLevel,
                verdictTitle,
                explanation,
                aggregatedSignals,
                latencyMs,
                Instant.now(),
                safeDisallowedByUnknown || (r3 != null && r3.fired() && aggregateThreatLevel == ThreatLevel.UNKNOWN)
        );

        return new IncidentFusionResponse(
                request.incidentId(),
                aggregateVerdict,
                ruleResults,
                contributions,
                coverageMap,
                request.ledgerVerified(),
                safeDisallowedByUnknown
        );
    }

    public List<FusionRule> getRules() {
        return List.copyOf(rules);
    }
}
