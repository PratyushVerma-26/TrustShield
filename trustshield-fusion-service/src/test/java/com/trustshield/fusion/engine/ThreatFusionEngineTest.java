package com.trustshield.fusion.engine;

import com.trustshield.common.dto.IncidentFusionRequest;
import com.trustshield.common.dto.IncidentFusionResponse;
import com.trustshield.common.dto.IncidentId;
import com.trustshield.common.dto.ModuleType;
import com.trustshield.common.dto.ModuleVerdict;
import com.trustshield.common.dto.ThreatLevel;
import com.trustshield.fusion.engine.rules.ConclusiveDangerousRule;
import com.trustshield.fusion.engine.rules.CoverageUnknownRule;
import com.trustshield.fusion.engine.rules.CrossModalCoordinationRule;
import com.trustshield.fusion.engine.rules.LedgerIntegrityOverrideRule;
import com.trustshield.fusion.engine.rules.MultimodalSuspiciousEscalationRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ThreatFusionEngineTest {

    private ThreatFusionEngine engine;

    @BeforeEach
    void setUp() {
        List<FusionRule> rules = List.of(
                new ConclusiveDangerousRule(),
                new MultimodalSuspiciousEscalationRule(),
                new CoverageUnknownRule(),
                new LedgerIntegrityOverrideRule(),
                new CrossModalCoordinationRule()
        );
        engine = new ThreatFusionEngine(rules, 15, 95);
    }

    @Test
    @DisplayName("Single conclusive DANGEROUS verdict elevates incident to DANGEROUS via Rule R1")
    void singleConclusiveDangerousMakesIncidentDangerous() {
        ModuleVerdict phishing = new ModuleVerdict(
                ModuleType.PHISHING,
                94,
                ThreatLevel.DANGEROUS,
                "GOOGLE_SAFEBROWSING_HIT",
                "Flagged as verified deceptive domain",
                List.of(),
                3L,
                Instant.now(),
                false
        );

        ModuleVerdict deepfake = new ModuleVerdict(
                ModuleType.DEEPFAKE,
                15,
                ThreatLevel.SAFE,
                "CLEAN_ELA",
                "Natural camera sensor noise",
                List.of(),
                12L,
                Instant.now(),
                false
        );

        IncidentFusionRequest request = new IncidentFusionRequest(IncidentId.generate(), List.of(phishing, deepfake), true);
        IncidentFusionResponse response = engine.fuseIncident(request);

        assertNotNull(response);
        assertEquals(ThreatLevel.DANGEROUS, response.aggregateVerdict().threatLevel());
        assertTrue(response.aggregateVerdict().riskScore() >= 90);
        assertEquals("CONCLUSIVE_DANGEROUS_ESCALATION", response.aggregateVerdict().verdict());
    }

    @Test
    @DisplayName("Two SUSPICIOUS modalities escalate incident to DANGEROUS via Rule R2")
    void twoSuspiciousModalitiesEscalateToDangerous() {
        ModuleVerdict breach = new ModuleVerdict(
                ModuleType.BREACH,
                55,
                ThreatLevel.SUSPICIOUS,
                "PASSWORD_HASH_COLLISION_BUCKET",
                "Password observed in breach corpus",
                List.of(),
                1L,
                Instant.now(),
                false
        );

        ModuleVerdict fakenews = new ModuleVerdict(
                ModuleType.FAKENEWS,
                50,
                ThreatLevel.SUSPICIOUS,
                "SENSATIONALIST_STYLE_CORRELATION",
                "High uppercase shouting and sensational punctuation",
                List.of(),
                8L,
                Instant.now(),
                false
        );

        IncidentFusionRequest request = new IncidentFusionRequest(IncidentId.generate(), List.of(breach, fakenews), true);
        IncidentFusionResponse response = engine.fuseIncident(request);

        assertEquals(ThreatLevel.DANGEROUS, response.aggregateVerdict().threatLevel());
        assertTrue(response.aggregateVerdict().riskScore() >= 75);
        assertEquals("MULTIMODAL_SUSPICIOUS_ESCALATION", response.aggregateVerdict().verdict());
    }

    @Test
    @DisplayName("Rule R3 enforces coverage invariant: unmeasured modality disallows certifying SAFE")
    void unknownModalityDisallowsSafe() {
        ModuleVerdict deepfakeUnknown = new ModuleVerdict(
                ModuleType.DEEPFAKE,
                0,
                ThreatLevel.UNKNOWN,
                "IMAGE_RECOMPRESSED",
                "Fine sensor noise destroyed by recompression",
                List.of(),
                10L,
                Instant.now(),
                true
        );

        ModuleVerdict phishingSafe = new ModuleVerdict(
                ModuleType.PHISHING,
                5,
                ThreatLevel.SAFE,
                "LEXICAL_CLEAN",
                "Standard domain without typosquatting",
                List.of(),
                2L,
                Instant.now(),
                false
        );

        IncidentFusionRequest request = new IncidentFusionRequest(IncidentId.generate(), List.of(phishingSafe, deepfakeUnknown), true);
        IncidentFusionResponse response = engine.fuseIncident(request);

        // Crucial invariant: never declare SAFE when a modality returned UNKNOWN
        assertEquals(ThreatLevel.UNKNOWN, response.aggregateVerdict().threatLevel());
        assertTrue(response.safeDisallowedByUnknown());
        assertEquals("INCONCLUSIVE_COVERAGE", response.aggregateVerdict().verdict());
    }

    @Test
    @DisplayName("Rule R4 overrides all modular scores if cryptographic ledger verification fails")
    void ledgerFailureOverridesToDangerousAndScore95() {
        ModuleVerdict clean1 = new ModuleVerdict(
                ModuleType.PHISHING,
                10,
                ThreatLevel.SAFE,
                "CLEAN",
                "Clean",
                List.of(),
                2L,
                Instant.now(),
                false
        );

        // ledgerVerified: false (audit chain broken or modified)
        IncidentFusionRequest request = new IncidentFusionRequest(IncidentId.generate(), List.of(clean1), false);
        IncidentFusionResponse response = engine.fuseIncident(request);

        assertEquals(ThreatLevel.DANGEROUS, response.aggregateVerdict().threatLevel());
        assertEquals(95, response.aggregateVerdict().riskScore());
        assertEquals("INCIDENT_INTEGRITY_TAMPERING", response.aggregateVerdict().verdict());
        assertFalse(response.ledgerVerified());
    }

    @Test
    @DisplayName("Rule R5 applies compound bonus for co-occurring phishing and synthetic deception")
    void crossModalSynergyAppliesCompoundBonus() {
        ModuleVerdict phishing = new ModuleVerdict(
                ModuleType.PHISHING,
                65,
                ThreatLevel.SUSPICIOUS,
                "TARGETED_SPEAR_PHISHING_LURE",
                "Internal portal imitation",
                List.of(),
                3L,
                Instant.now(),
                false
        );

        ModuleVerdict deepfake = new ModuleVerdict(
                ModuleType.DEEPFAKE,
                65,
                ThreatLevel.SUSPICIOUS,
                "SYNTHETIC_VOCODER_PITCH",
                "AI voice clone characteristics",
                List.of(),
                14L,
                Instant.now(),
                false
        );

        IncidentFusionRequest request = new IncidentFusionRequest(IncidentId.generate(), List.of(phishing, deepfake), true);
        IncidentFusionResponse response = engine.fuseIncident(request);

        assertEquals(ThreatLevel.DANGEROUS, response.aggregateVerdict().threatLevel());
        assertTrue(response.aggregateVerdict().riskScore() >= 80);
    }

    @Test
    @DisplayName("Empty verdicts returns UNKNOWN with score 0 and no crash")
    void emptyVerdictsReturnsUnknown() {
        IncidentFusionRequest request = new IncidentFusionRequest(IncidentId.generate(), List.of(), true);
        IncidentFusionResponse response = engine.fuseIncident(request);

        assertEquals(ThreatLevel.UNKNOWN, response.aggregateVerdict().threatLevel());
        assertEquals(0, response.aggregateVerdict().riskScore());
        assertEquals("NO_MODALITIES_EVALUATED", response.aggregateVerdict().verdict());
    }
}
