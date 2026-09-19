package com.trustshield.fakenews.entity;

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
 * JPA entity recording historical misinformation claim verification outcomes.
 */
@Entity
@Table(
        name = "claim_check",
        indexes = {
                @Index(name = "idx_claim_check_incident_id", columnList = "incident_id"),
                @Index(name = "idx_claim_check_checked_at", columnList = "checked_at")
        }
)
public class ClaimCheckRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "incident_id", length = 64)
    private String incidentId;

    @Column(name = "claim_text", length = 1024, nullable = false)
    private String claimText;

    @Column(name = "context", length = 64)
    private String context;

    @Column(name = "risk_score", nullable = false)
    private int riskScore;

    @Enumerated(EnumType.STRING)
    @Column(name = "threat_level", nullable = false, length = 16)
    private ThreatLevel threatLevel;

    @Column(name = "primary_signal", length = 64)
    private String primarySignal;

    @Column(name = "explanation", length = 512)
    private String explanation;

    @Column(name = "degraded", nullable = false)
    private boolean degraded;

    @Column(name = "fact_check_consulted", nullable = false)
    private boolean factCheckConsulted;

    @Column(name = "fact_check_matched", nullable = false)
    private boolean factCheckMatched;

    @Column(name = "fact_check_publisher", length = 128)
    private String factCheckPublisher;

    @Column(name = "sim_hash_matched", nullable = false)
    private boolean simHashMatched;

    @Column(name = "sim_hash_similarity", nullable = false)
    private double simHashSimilarity;

    @Column(name = "style_risk_score", nullable = false)
    private int styleRiskScore;

    @Column(name = "checked_at", nullable = false)
    private Instant checkedAt;

    @Column(name = "latency_ms")
    private long latencyMs;

    public ClaimCheckRecord() {
    }

    public ClaimCheckRecord(
            String incidentId,
            String claimText,
            String context,
            int riskScore,
            ThreatLevel threatLevel,
            String primarySignal,
            String explanation,
            boolean degraded,
            boolean factCheckConsulted,
            boolean factCheckMatched,
            String factCheckPublisher,
            boolean simHashMatched,
            double simHashSimilarity,
            int styleRiskScore,
            Instant checkedAt,
            long latencyMs) {
        this.incidentId = incidentId;
        this.claimText = claimText != null && claimText.length() > 1000 ? claimText.substring(0, 1000) : claimText;
        this.context = context;
        this.riskScore = riskScore;
        this.threatLevel = threatLevel;
        this.primarySignal = primarySignal;
        this.explanation = explanation != null && explanation.length() > 500 ? explanation.substring(0, 500) : explanation;
        this.degraded = degraded;
        this.factCheckConsulted = factCheckConsulted;
        this.factCheckMatched = factCheckMatched;
        this.factCheckPublisher = factCheckPublisher;
        this.simHashMatched = simHashMatched;
        this.simHashSimilarity = simHashSimilarity;
        this.styleRiskScore = styleRiskScore;
        this.checkedAt = checkedAt != null ? checkedAt : Instant.now();
        this.latencyMs = latencyMs;
    }

    public Long getId() {
        return id;
    }

    public String getIncidentId() {
        return incidentId;
    }

    public String getClaimText() {
        return claimText;
    }

    public String getContext() {
        return context;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public ThreatLevel getThreatLevel() {
        return threatLevel;
    }

    public String getPrimarySignal() {
        return primarySignal;
    }

    public String getExplanation() {
        return explanation;
    }

    public boolean isDegraded() {
        return degraded;
    }

    public boolean isFactCheckConsulted() {
        return factCheckConsulted;
    }

    public boolean isFactCheckMatched() {
        return factCheckMatched;
    }

    public String getFactCheckPublisher() {
        return factCheckPublisher;
    }

    public boolean isSimHashMatched() {
        return simHashMatched;
    }

    public double getSimHashSimilarity() {
        return simHashSimilarity;
    }

    public int getStyleRiskScore() {
        return styleRiskScore;
    }

    public Instant getCheckedAt() {
        return checkedAt;
    }

    public long getLatencyMs() {
        return latencyMs;
    }
}
