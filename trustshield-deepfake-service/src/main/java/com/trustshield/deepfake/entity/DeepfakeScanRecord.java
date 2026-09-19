package com.trustshield.deepfake.entity;

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
 * JPA entity recording historical deepfake image forensic evaluations.
 */
@Entity
@Table(
        name = "deepfake_scan",
        indexes = {
                @Index(name = "idx_deepfake_scan_incident_id", columnList = "incident_id"),
                @Index(name = "idx_deepfake_scan_scanned_at", columnList = "scanned_at")
        }
)
public class DeepfakeScanRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "incident_id", length = 64)
    private String incidentId;

    @Column(name = "filename", length = 255)
    private String filename;

    @Column(name = "format", length = 32)
    private String format;

    @Column(name = "width")
    private int width;

    @Column(name = "height")
    private int height;

    @Column(name = "size_bytes")
    private long sizeBytes;

    @Column(name = "risk_score", nullable = false)
    private int riskScore;

    @Enumerated(EnumType.STRING)
    @Column(name = "threat_level", nullable = false, length = 16)
    private ThreatLevel threatLevel;

    @Column(name = "verdict", nullable = false, length = 64)
    private String verdict;

    @Column(name = "explanation", length = 1024)
    private String explanation;

    @Column(name = "ela_variance")
    private double elaVariance;

    @Column(name = "dqt_anomalous")
    private boolean quantisationTableAnomalous;

    @Column(name = "dqt_fingerprint", length = 64)
    private String quantisationTableFingerprint;

    @Column(name = "blockiness_score")
    private double spatialBlockinessScore;

    @Column(name = "noise_residual_variance")
    private double noiseResidualVariance;

    @Column(name = "metadata_inconsistent")
    private boolean metadataInconsistent;

    @Column(name = "c2pa_detected")
    private boolean c2paDetected;

    @Column(name = "recompression_detected")
    private boolean recompressionDetected;

    @Column(name = "latency_ms", nullable = false)
    private long latencyMs;

    @Column(name = "degraded", nullable = false)
    private boolean degraded;

    @Column(name = "context", length = 64)
    private String context;

    @Column(name = "scanned_at", nullable = false)
    private Instant scannedAt;

    protected DeepfakeScanRecord() {
        // Required by JPA
    }

    public DeepfakeScanRecord(
            String incidentId,
            String filename,
            String format,
            int width,
            int height,
            long sizeBytes,
            int riskScore,
            ThreatLevel threatLevel,
            String verdict,
            String explanation,
            double elaVariance,
            boolean quantisationTableAnomalous,
            String quantisationTableFingerprint,
            double spatialBlockinessScore,
            double noiseResidualVariance,
            boolean metadataInconsistent,
            boolean c2paDetected,
            boolean recompressionDetected,
            long latencyMs,
            boolean degraded,
            String context,
            Instant scannedAt
    ) {
        this.incidentId = incidentId;
        this.filename = filename;
        this.format = format;
        this.width = width;
        this.height = height;
        this.sizeBytes = sizeBytes;
        this.riskScore = riskScore;
        this.threatLevel = threatLevel;
        this.verdict = verdict;
        this.explanation = explanation;
        this.elaVariance = elaVariance;
        this.quantisationTableAnomalous = quantisationTableAnomalous;
        this.quantisationTableFingerprint = quantisationTableFingerprint;
        this.spatialBlockinessScore = spatialBlockinessScore;
        this.noiseResidualVariance = noiseResidualVariance;
        this.metadataInconsistent = metadataInconsistent;
        this.c2paDetected = c2paDetected;
        this.recompressionDetected = recompressionDetected;
        this.latencyMs = latencyMs;
        this.degraded = degraded;
        this.context = context;
        this.scannedAt = scannedAt;
    }

    public Long getId() {
        return id;
    }

    public String getIncidentId() {
        return incidentId;
    }

    public String getFilename() {
        return filename;
    }

    public String getFormat() {
        return format;
    }

    public int getWidth() {
        return width;
    }

    public int getHeight() {
        return height;
    }

    public long getSizeBytes() {
        return sizeBytes;
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

    public double getElaVariance() {
        return elaVariance;
    }

    public boolean isQuantisationTableAnomalous() {
        return quantisationTableAnomalous;
    }

    public String getQuantisationTableFingerprint() {
        return quantisationTableFingerprint;
    }

    public double getSpatialBlockinessScore() {
        return spatialBlockinessScore;
    }

    public double getNoiseResidualVariance() {
        return noiseResidualVariance;
    }

    public boolean isMetadataInconsistent() {
        return metadataInconsistent;
    }

    public boolean isC2paDetected() {
        return c2paDetected;
    }

    public boolean isRecompressionDetected() {
        return recompressionDetected;
    }

    public long getLatencyMs() {
        return latencyMs;
    }

    public boolean isDegraded() {
        return degraded;
    }

    public String getContext() {
        return context;
    }

    public Instant getScannedAt() {
        return scannedAt;
    }
}
