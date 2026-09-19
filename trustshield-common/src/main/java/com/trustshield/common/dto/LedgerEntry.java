package com.trustshield.common.dto;

import java.time.Instant;
import java.util.Objects;

/**
 * A single tamper-evident entry in the append-only hash chain.
 *
 * <p>Formula:
 * {@code entryHash = SHA-256(canonicalPayload)}
 * {@code chainHash = SHA-256(previousChainHash + entryHash)}
 *
 * @param sequenceNumber zero-based index in the ledger
 * @param incidentId correlation identifier
 * @param module which detector produced the event
 * @param entryHash SHA-256 of canonicalPayload
 * @param previousChainHash chainHash of sequenceNumber - 1 (or 64 zeros for genesis)
 * @param chainHash SHA-256(previousChainHash || entryHash)
 * @param canonicalPayload raw canonical JSON payload
 * @param timestamp when this entry was committed
 */
public record LedgerEntry(
        long sequenceNumber,
        IncidentId incidentId,
        ModuleType module,
        String entryHash,
        String previousChainHash,
        String chainHash,
        String canonicalPayload,
        Instant timestamp
) {
    public LedgerEntry {
        Objects.requireNonNull(incidentId, "incidentId must not be null");
        Objects.requireNonNull(module, "module must not be null");
        Objects.requireNonNull(entryHash, "entryHash must not be null");
        Objects.requireNonNull(previousChainHash, "previousChainHash must not be null");
        Objects.requireNonNull(chainHash, "chainHash must not be null");
        Objects.requireNonNull(canonicalPayload, "canonicalPayload must not be null");
        timestamp = timestamp == null ? Instant.now() : timestamp;
    }
}
