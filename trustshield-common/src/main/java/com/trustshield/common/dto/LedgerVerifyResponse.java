package com.trustshield.common.dto;

/**
 * Outcome of verifying the entire integrity ledger hash chain.
 *
 * <p>When corruption or tampering is detected, {@code firstCorruptedIndex} names
 * the exact first bad index, and specifies that all subsequent entries are
 * unverifiable rather than merely wrong.
 *
 * @param valid true if every chain link and digital signature is valid
 * @param firstCorruptedIndex null if valid, or the 0-based index where chain hash broke
 * @param failureReason explanation of the verification outcome
 * @param totalEntriesChecked total number of entries traversed
 * @param headChainHash verified head hash
 * @param signatureValid whether the Ed25519 head signature verified
 */
public record LedgerVerifyResponse(
        boolean valid,
        Long firstCorruptedIndex,
        String failureReason,
        long totalEntriesChecked,
        String headChainHash,
        boolean signatureValid
) {
    public static LedgerVerifyResponse success(long count, String headHash, boolean sigValid) {
        return new LedgerVerifyResponse(true, null, "Ledger integrity intact. All hashes and signatures valid.", count, headHash, sigValid);
    }

    public static LedgerVerifyResponse corrupted(long firstBadIndex, String reason, long count, String headHash) {
        return new LedgerVerifyResponse(false, firstBadIndex, reason, count, headHash, false);
    }
}
