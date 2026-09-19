package com.trustshield.breach.entity;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

import com.trustshield.common.dto.ThreatLevel;

/**
 * Audit record of a breach verification query.
 *
 * <p>Enforces privacy-by-design and data minimization at the schema level:
 * <ul>
 *   <li><strong>Passwords:</strong> Only {@code bucketPrefix} (the 5-character SHA-1 prefix)
 *       is retained; plaintext and remaining hash characters are never persisted.</li>
 *   <li><strong>Email addresses:</strong> Pseudonymized via SHA-256 ({@code subjectHash})
 *       to support historical query correlation without retaining plaintext PII.</li>
 * </ul>
 */
@Entity
@Table(name = "breach_check_record", indexes = {
        @Index(name = "idx_breach_checked_at", columnList = "checked_at"),
        @Index(name = "idx_breach_subject_hash", columnList = "subject_hash")
})
public class BreachCheckRecord {

    public enum CheckType {
        PASSWORD,
        EMAIL
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name = "check_type", nullable = false, length = 16)
    private CheckType checkType;

    /** 5-hex-character k-anonymity bucket. Null for email checks. */
    @Column(name = "bucket_prefix", length = 5)
    private String bucketPrefix;

    /** SHA-256 of the lower-cased email. Null for password checks. */
    @Column(name = "subject_hash", length = 64)
    private String subjectHash;

    @Column(name = "risk_score", nullable = false)
    private int riskScore;

    @Enumerated(EnumType.STRING)
    @Column(name = "threat_level", nullable = false, length = 16)
    private ThreatLevel threatLevel;

    @Column(nullable = false, length = 48)
    private String verdict;

    @Column(nullable = false)
    private boolean exposed;

    /** True when at least one intended source could not be consulted. */
    @Column(nullable = false)
    private boolean degraded;

    /** Which sources answered, e.g. "PWNED_PASSWORDS_RANGE_API=UNAVAILABLE". */
    @Column(name = "source_summary", length = 512)
    private String sourceSummary;

    @Column(length = 32)
    private String context;

    @Column(name = "checked_at", nullable = false)
    private Instant checkedAt;

    protected BreachCheckRecord() {
        // JPA
    }

    private BreachCheckRecord(CheckType checkType) {
        this.checkType = checkType;
        this.checkedAt = Instant.now();
    }

    public static BreachCheckRecord forPassword(String bucketPrefix) {
        BreachCheckRecord r = new BreachCheckRecord(CheckType.PASSWORD);
        r.bucketPrefix = bucketPrefix;
        return r;
    }

    public static BreachCheckRecord forEmail(String subjectHash) {
        BreachCheckRecord r = new BreachCheckRecord(CheckType.EMAIL);
        r.subjectHash = subjectHash;
        return r;
    }

    public BreachCheckRecord withOutcome(int riskScore,
                                         ThreatLevel threatLevel,
                                         String verdict,
                                         boolean exposed,
                                         boolean degraded,
                                         String sourceSummary,
                                         String context) {
        this.riskScore = riskScore;
        this.threatLevel = threatLevel;
        this.verdict = verdict;
        this.exposed = exposed;
        this.degraded = degraded;
        this.sourceSummary = truncate(sourceSummary, 512);
        this.context = truncate(context, 32);
        return this;
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return null;
        }
        return s.length() <= max ? s : s.substring(0, max);
    }

    public Long getId() {
        return id;
    }

    public CheckType getCheckType() {
        return checkType;
    }

    public String getBucketPrefix() {
        return bucketPrefix;
    }

    public String getSubjectHash() {
        return subjectHash;
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

    public boolean isExposed() {
        return exposed;
    }

    public boolean isDegraded() {
        return degraded;
    }

    public String getSourceSummary() {
        return sourceSummary;
    }

    public String getContext() {
        return context;
    }

    public Instant getCheckedAt() {
        return checkedAt;
    }
}
