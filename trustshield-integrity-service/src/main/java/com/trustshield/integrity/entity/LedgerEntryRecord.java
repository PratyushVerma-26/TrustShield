package com.trustshield.integrity.entity;

import com.trustshield.common.dto.ModuleType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * JPA entity persisting a single link in the append-only SHA-256 hash chain.
 */
@Entity
@Table(
        name = "ledger_entry",
        indexes = {
                @Index(name = "idx_ledger_incident_id", columnList = "incident_id"),
                @Index(name = "idx_ledger_committed_at", columnList = "committed_at")
        }
)
public class LedgerEntryRecord {

    @Id
    @Column(name = "sequence_number", nullable = false)
    private Long sequenceNumber;

    @Column(name = "incident_id", length = 64, nullable = false)
    private String incidentId;

    @Enumerated(EnumType.STRING)
    @Column(name = "module", length = 32, nullable = false)
    private ModuleType module;

    @Column(name = "entry_hash", length = 64, nullable = false)
    private String entryHash;

    @Column(name = "previous_chain_hash", length = 64, nullable = false)
    private String previousChainHash;

    @Column(name = "chain_hash", length = 64, nullable = false)
    private String chainHash;

    @Lob
    @Column(name = "canonical_payload", columnDefinition = "TEXT", nullable = false)
    private String canonicalPayload;

    @Column(name = "committed_at", nullable = false)
    private Instant committedAt;

    public LedgerEntryRecord() {
    }

    public LedgerEntryRecord(
            Long sequenceNumber,
            String incidentId,
            ModuleType module,
            String entryHash,
            String previousChainHash,
            String chainHash,
            String canonicalPayload,
            Instant committedAt) {
        this.sequenceNumber = sequenceNumber;
        this.incidentId = incidentId;
        this.module = module;
        this.entryHash = entryHash;
        this.previousChainHash = previousChainHash;
        this.chainHash = chainHash;
        this.canonicalPayload = canonicalPayload;
        this.committedAt = committedAt != null ? committedAt : Instant.now();
    }

    public Long getSequenceNumber() {
        return sequenceNumber;
    }

    public String getIncidentId() {
        return incidentId;
    }

    public ModuleType getModule() {
        return module;
    }

    public String getEntryHash() {
        return entryHash;
    }

    public String getPreviousChainHash() {
        return previousChainHash;
    }

    public String getChainHash() {
        return chainHash;
    }

    public String getCanonicalPayload() {
        return canonicalPayload;
    }

    public void setCanonicalPayload(String canonicalPayload) {
        this.canonicalPayload = canonicalPayload;
    }

    public Instant getCommittedAt() {
        return committedAt;
    }
}
