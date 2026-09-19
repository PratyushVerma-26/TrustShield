package com.trustshield.common.dto;

import java.time.Instant;
import java.util.Objects;

/**
 * Current head state of the integrity ledger.
 *
 * <p>Includes an Ed25519 digital signature of the head chain hash, proving
 * authenticity against anyone lacking the server's private key.
 *
 * @param sequenceNumber index of the latest entry
 * @param headChainHash latest cumulative chain hash
 * @param ed25519SignatureHex Ed25519 signature of the headChainHash
 * @param publicKeyBase64 public key to verify the signature
 * @param timestamp time head was queried
 */
public record LedgerHeadResponse(
        long sequenceNumber,
        String headChainHash,
        String ed25519SignatureHex,
        String publicKeyBase64,
        Instant timestamp
) {
    public LedgerHeadResponse {
        Objects.requireNonNull(headChainHash, "headChainHash must not be null");
        timestamp = timestamp == null ? Instant.now() : timestamp;
    }
}
