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
 * Audit record of a breach check.
 *
 * <h2>What is deliberately not stored</h2>
 *
 * <p>Neither the password nor the email address is persisted, in any form that
 * could be reversed:
 *
 * <ul>
 *   <li><strong>Passwords:</strong> only {@code bucketPrefix}, the 5 hex
 *       characters of the SHA-1 that the k-anonymity protocol already discloses
 *       to the API. One bucket in 16^5 covers roughly a millionth of the hash
 *       space, so the record cannot identify the password even in principle. The
 *       remaining 35 characters are never written anywhere.</li>
 *   <li><strong>Email addresses:</strong> only {@code subjectHash}, a SHA-256 of
 *       the lower-cased address. This supports "have I checked this before"
 *       without the database holding personal data. Note the honest limitation:
 *       an email address has low entropy, so a hash is pseudonymisation, not
 *       anonymisation — someone with a candidate list can confirm a guess. It is
 *       a real improvement over plaintext, not a guarantee.</li>
 * </ul>
 *
 * <p>This is the data-minimisation principle of the DPDP Act 2023 applied at the
 * schema level, where it cannot be forgotten later, rather than as a policy note.
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
