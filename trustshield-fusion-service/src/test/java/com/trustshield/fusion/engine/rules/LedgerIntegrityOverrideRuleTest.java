package com.trustshield.fusion.engine.rules;

import com.trustshield.common.dto.FusionRuleResult;
import com.trustshield.common.dto.IncidentFusionRequest;
import com.trustshield.common.dto.IncidentId;
import com.trustshield.common.dto.ModuleType;
import com.trustshield.common.dto.ModuleVerdict;
import com.trustshield.common.dto.ThreatLevel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LedgerIntegrityOverrideRuleTest {

    private LedgerIntegrityOverrideRule rule;

    @BeforeEach
    void setUp() {
        rule = new LedgerIntegrityOverrideRule();
    }

    @Test
    @DisplayName("R4 fires when cryptographic ledger check fails (ledgerVerified == false)")
    void firesOnLedgerVerificationFailure() {
        ModuleVerdict v1 = new ModuleVerdict(
                ModuleType.PHISHING,
                10,
                ThreatLevel.SAFE,
                "LEXICAL_CLEAN",
                "Clean domain",
                List.of(),
                3L,
                Instant.now(),
                false
        );

        // ledgerVerified: false (cryptographic tamper breach)
        IncidentFusionRequest request = new IncidentFusionRequest(IncidentId.generate(), List.of(v1), false);
        Map<ModuleType, ModuleVerdict> contributions = Map.of(ModuleType.PHISHING, v1);

        FusionRuleResult result = rule.evaluate(request, contributions);

        assertTrue(result.fired());
        assertEquals("R4", result.ruleId());
        assertEquals(ThreatLevel.DANGEROUS, result.resultingLevel());
    }

    @Test
    @DisplayName("R4 does not fire when cryptographic ledger check succeeds")
    void doesNotFireWhenLedgerVerified() {
        IncidentFusionRequest request = new IncidentFusionRequest(IncidentId.generate(), List.of(), true);
        FusionRuleResult result = rule.evaluate(request, Map.of());

        assertFalse(result.fired());
    }
}
