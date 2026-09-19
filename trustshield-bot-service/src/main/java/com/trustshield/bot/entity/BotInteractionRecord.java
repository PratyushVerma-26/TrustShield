package com.trustshield.bot.entity;

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
 * JPA entity recording conversational threat queries from WhatsApp, Telegram, and Web Chat.
 */
@Entity
@Table(
        name = "bot_interaction",
        indexes = {
                @Index(name = "idx_bot_incident_id", columnList = "incident_id"),
                @Index(name = "idx_bot_sender_id", columnList = "sender_id"),
                @Index(name = "idx_bot_created_at", columnList = "created_at"),
                @Index(name = "idx_bot_threat_level", columnList = "threat_level")
        }
)
public class BotInteractionRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "incident_id", length = 64, nullable = false)
    private String incidentId;

    @Column(name = "channel", length = 32, nullable = false)
    private String channel;

    @Column(name = "sender_id", length = 128, nullable = false)
    private String senderId;

    @Column(name = "intent", length = 32, nullable = false)
    private String intent;

    @Enumerated(EnumType.STRING)
    @Column(name = "threat_level", nullable = false, length = 16)
    private ThreatLevel threatLevel;

    @Column(name = "risk_score", nullable = false)
    private int riskScore;

    @Column(name = "primary_category", length = 64, nullable = false)
    private String primaryCategory;

    @Column(name = "query_text", length = 4096)
    private String queryText;

    @Column(name = "latency_ms", nullable = false)
    private long latencyMs;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    public BotInteractionRecord() {}

    public BotInteractionRecord(
            String incidentId,
            String channel,
            String senderId,
            String intent,
            ThreatLevel threatLevel,
            int riskScore,
            String primaryCategory,
            String queryText,
            long latencyMs,
            Instant createdAt) {
        this.incidentId = incidentId;
        this.channel = channel;
        this.senderId = senderId;
        this.intent = intent;
        this.threatLevel = threatLevel;
        this.riskScore = riskScore;
        this.primaryCategory = primaryCategory;
        this.queryText = queryText;
        this.latencyMs = latencyMs;
        this.createdAt = createdAt != null ? createdAt : Instant.now();
    }

    public Long getId() {
        return id;
    }

    public String getIncidentId() {
        return incidentId;
    }

    public String getChannel() {
        return channel;
    }

    public String getSenderId() {
        return senderId;
    }

    public String getIntent() {
        return intent;
    }

    public ThreatLevel getThreatLevel() {
        return threatLevel;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public String getPrimaryCategory() {
        return primaryCategory;
    }

    public String getQueryText() {
        return queryText;
    }

    public long getLatencyMs() {
        return latencyMs;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
