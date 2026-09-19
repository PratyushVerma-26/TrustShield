package com.trustshield.fusion.engine.rules;

import com.trustshield.common.dto.FusionRuleResult;
import com.trustshield.common.dto.IncidentFusionRequest;
import com.trustshield.common.dto.ModuleType;
import com.trustshield.common.dto.ModuleVerdict;
import com.trustshield.common.dto.ThreatLevel;
import com.trustshield.fusion.engine.FusionRule;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Fusion Rule R4: Cryptographic Ledger Tamper Override.
 *
 * <p>Invariant: If the cryptographic audit ledger verification fails ({@code !ledgerVerified}),
 * the incident is overridden immediately with {@link ThreatLevel#DANGEROUS} and flagged for systemic tampering.
 *
 * <p>Rationale: Cryptographic non-repudiation supersedes heuristic threat scores. If a database record
 * or SHA-256 hash chain shows evidence of tampering, the incident cannot be trusted regardless of scanner outputs.
 */
@Component
@Order(4)
public class LedgerIntegrityOverrideRule implements FusionRule {

    public static final String RULE_ID = "R4";
    public static final String RULE_NAME = "Cryptographic Ledger Tamper Override";
    public static final String DESCRIPTION =
            "Failure of cryptographic ledger verification overrides modular verdicts and marks the incident DANGEROUS.";

    @Override
    public String getRuleId() {
        return RULE_ID;
    }

    @Override
    public String getRuleName() {
        return RULE_NAME;
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    @Override
    public FusionRuleResult evaluate(IncidentFusionRequest request, Map<ModuleType, ModuleVerdict> contributions) {
        boolean failed = !request.ledgerVerified();

        return new FusionRuleResult(
                RULE_ID,
                RULE_NAME,
                DESCRIPTION,
                failed,
                failed ? ThreatLevel.DANGEROUS : null
        );
    }
}
