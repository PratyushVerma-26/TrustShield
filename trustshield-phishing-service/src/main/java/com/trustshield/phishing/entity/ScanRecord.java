package com.trustshield.phishing.entity;

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
 * Persisted record of one URL scan.
 *
 * <p>Privacy note, which matters for the report: a scanned URL can itself be
 * personal data — it may carry a session token, an account number, or reveal
 * browsing behaviour. Under India's Digital Personal Data Protection Act 2023
 * that makes retention a design decision rather than a default. Two things follow
 * in this schema: {@code urlHash} exists so repeat-lookup and aggregate
 * statistics can be done without reading the URL itself, and {@code host} is
 * stored separately so analytics can run at domain granularity. A retention job
 * that drops the {@code url} column after a configurable window is listed in the
 * roadmap and is not yet implemented — stated plainly rather than implied.
 */
@Entity
@Table(
        name = "phishing_scan",
        indexes = {
                @Index(name = "idx_phishing_scan_url_hash", columnList = "url_hash"),
                @Index(name = "idx_phishing_scan_scanned_at", columnList = "scanned_at"),
                @Index(name = "idx_phishing_scan_host", columnList = "host")
        }
)
public class ScanRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "url", nullable = false, length = 2048)
    private String url;

    /** SHA-256 of the URL, for dedup and aggregate counts without reading the URL. */
    @Column(name = "url_hash", nullable = false, length = 64)
    private String urlHash;

    @Column(name = "host", length = 255)
    private String host;

    @Column(name = "risk_score", nullable = false)
    private int riskScore;

    @Enumerated(EnumType.STRING)
    @Column(name = "threat_level", nullable = false, length = 16)
    private ThreatLevel threatLevel;

    @Column(name = "verdict", nullable = false, length = 64)
    private String verdict;

    @Column(name = "explanation", length = 1024)
    private String explanation;

    @Column(name = "latency_ms", nullable = false)
    private long latencyMs;

    @Column(name = "degraded", nullable = false)
    private boolean degraded;

    @Column(name = "model_version", length = 64)
    private String modelVersion;

    /** TRAINED or HEURISTIC_BOOTSTRAP. Recorded so old scans can be excluded
     *  from any evaluation once a real model replaces the bootstrap. */
    @Column(name = "model_provenance", length = 32)
    private String modelProvenance;

    @Column(name = "source_context", length = 32)
    private String sourceContext;

    @Column(name = "scanned_at", nullable = false)
    private Instant scannedAt;

    protected ScanRecord() {
        // Required by JPA.
    }

    public ScanRecord(String url, String urlHash, String host, int riskScore,
                      ThreatLevel threatLevel, String verdict, String explanation,
                      long latencyMs, boolean degraded, String modelVersion,
                      String modelProvenance, String sourceContext, Instant scannedAt) {
        this.url = url;
        this.urlHash = urlHash;
        this.host = host;
        this.riskScore = riskScore;
        this.threatLevel = threatLevel;
        this.verdict = verdict;
        this.explanation = explanation;
        this.latencyMs = latencyMs;
        this.degraded = degraded;
        this.modelVersion = modelVersion;
        this.modelProvenance = modelProvenance;
        this.sourceContext = sourceContext;
        this.scannedAt = scannedAt;
    }

    public Long getId() {
        return id;
    }

    public String getUrl() {
        return url;
    }

    public String getUrlHash() {
        return urlHash;
    }

    public String getHost() {
        return host;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public ThreatLevel getThreatLevel() {
        return threatLevel;
    }

    public String getVerdict() {
        return verdict;
    }

    public String getExplanation() {
        return explanation;
    }

    public long getLatencyMs() {
        return latencyMs;
    }

    public boolean isDegraded() {
        return degraded;
    }

    public String getModelVersion() {
        return modelVersion;
    }

    public String getModelProvenance() {
        return modelProvenance;
    }

    public String getSourceContext() {
        return sourceContext;
    }

    public Instant getScannedAt() {
        return scannedAt;
    }
}
