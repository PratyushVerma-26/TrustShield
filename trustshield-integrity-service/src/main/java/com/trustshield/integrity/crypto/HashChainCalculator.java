package com.trustshield.integrity.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Deterministic SHA-256 hash calculator for ledger entries and cumulative chain hashes.
 *
 * <p>Formulas:
 * <ul>
 *   <li>{@code entryHash = SHA-256(canonicalPayload)}</li>
 *   <li>{@code chainHash = SHA-256(previousChainHash + entryHash)}</li>
 * </ul>
 */
public final class HashChainCalculator {

    public static final String GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";
    private static final HexFormat HEX = HexFormat.of();

    private HashChainCalculator() {
        // Utility class
    }

    /**
     * Computes the lowercase 64-character SHA-256 hex digest of the canonical UTF-8 text.
     */
    public static String sha256Hex(String text) {
        if (text == null) {
            throw new IllegalArgumentException("Payload cannot be null");
        }
        return sha256Hex(text.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Computes the lowercase 64-character SHA-256 hex digest of the raw byte array.
     */
    public static String sha256Hex(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            return HEX.formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm unavailable in runtime", e);
        }
    }

    /**
     * Computes {@code entryHash = SHA-256(canonicalPayload)}.
     */
    public static String calculateEntryHash(String canonicalPayload) {
        return sha256Hex(canonicalPayload);
    }

    /**
     * Computes {@code chainHash = SHA-256(previousChainHash + entryHash)}.
     */
    public static String calculateChainHash(String previousChainHash, String entryHash) {
        if (previousChainHash == null || previousChainHash.isBlank()) {
            previousChainHash = GENESIS_HASH;
        }
        if (entryHash == null || entryHash.isBlank()) {
            throw new IllegalArgumentException("entryHash must not be null or blank");
        }
        return sha256Hex(previousChainHash + entryHash);
    }

    /**
     * Performs constant-time comparison of two cryptographic hash strings to prevent timing attacks.
     */
    public static boolean constantTimeEquals(String hash1, String hash2) {
        if (hash1 == null || hash2 == null) {
            return false;
        }
        byte[] b1 = hash1.toLowerCase().getBytes(StandardCharsets.UTF_8);
        byte[] b2 = hash2.toLowerCase().getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(b1, b2);
    }
}
