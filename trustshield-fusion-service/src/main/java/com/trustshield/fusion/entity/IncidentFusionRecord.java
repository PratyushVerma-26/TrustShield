package com.trustshield.fusion.entity;

import com.trustshield.common.dto.ThreatLevel;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * JPA entity recording historical cross-modal incident risk fusion evaluations.
 */
@Entity
@Table(
        name = "incident_fusion",
        indexes = {
                @Index(name = "idx_fusion_incident_id", columnList = "incident_id"),
                @Index(name = "idx_fusion_evaluated_at", columnList = "evaluated_at"),
                @Index(name = "idx_fusion_threat_level", columnList = "threat_level")
        }
)
public class IncidentFusionRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "incident_id", length = 64, nullable = false)
    private String incidentId;

    @Column(name = "risk_score", nullable = false)
    private int riskScore;

    @Enumerated(EnumType.STRING)
    @Column(name = "threat_level", nullable = false, length = 16)
    private ThreatLevel threatLevel;

    @Column(name = "verdict_title", length = 64, nullable = false)
    private String verdictTitle;

    @Column(name = "explanation", length = 1024)
    private String explanation;

    @Column(name = "fired_rules_count", nullable = false)
    private int firedRulesCount;

    @Column(name = "contributing_modules_count", nullable = false)
    private int contributingModulesCount;

    @Column(name = "ledger_verified", nullable = false)
    private boolean ledgerVerified;

    @Column(name = "safe_disallowed", nullable = false)
    private boolean safeDisallowed;

    @Column(name = "evaluated_at", nullable = false)
    private Instant evaluatedAt;

    @Column(name = "latency_ms", nullable = false)
    private long latencyMs;

    public IncidentFusionRecord() {}

    public IncidentFusionRecord(
            String incidentId,
            int riskScore,
            ThreatLevel threatLevel,
            String verdictTitle,
            String explanation,
            int firedRulesCount,
            int contributingModulesCount,
            boolean ledgerVerified,
            boolean safeDisallowed,
            Instant evaluatedAt,
            long latencyMs) {
        this.incidentId = incidentId;
        this.riskScore = riskScore;
        this.threatLevel = threatLevel;
        this.verdictTitle = verdictTitle;
        this.explanation = explanation;
        this.firedRulesCount = firedRulesCount;
        this.contributingModulesCount = contributingModulesCount;
        this.ledgerVerified = ledgerVerified;
        this.safeDisallowed = safeDisallowed;
        this.evaluatedAt = evaluatedAt;
        this.latencyMs = latencyMs;
    }

    public Long getId() {
        return id;
    }

    public String getIncidentId() {
        return incidentId;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public ThreatLevel getThreatLevel() {
        return threatLevel;
    }

    public String getVerdictTitle() {
        return verdictTitle;
    }

    public String getExplanation() {
        return explanation;
    }

    public int getFiredRulesCount() {
        return firedRulesCount;
    }

    public int getContributingModulesCount() {
        return contributingModulesCount;
    }

    public boolean isLedgerVerified() {
        return ledgerVerified;
    }

    public boolean isSafeDisallowed() {
        return safeDisallowed;
    }

    public Instant getEvaluatedAt() {
        return evaluatedAt;
    }

    public long getLatencyMs() {
        return latencyMs;
    }
}
