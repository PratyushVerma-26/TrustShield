package com.trustshield.common.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Hashing helpers shared across services.
 *
 * <p>Deliberately uses {@link MessageDigest} from the JDK rather than an external
 * crypto library. Note that the original project draft used
 * {@code javax.xml.bind.DatatypeConverter} for hex conversion; that class was
 * removed from the JDK in Java 11 and will not compile on Java 21, so hex
 * encoding is implemented directly here.
 */
public final class HashUtils {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private HashUtils() {
    }

    /** Lower-case hex SHA-256 of a UTF-8 string. */
    public static String sha256Hex(String input) {
        return toHex(digest("SHA-256", input.getBytes(StandardCharsets.UTF_8)));
    }

    /** Lower-case hex SHA-256 of raw bytes, e.g. an uploaded media file. */
    public static String sha256Hex(byte[] input) {
        return toHex(digest("SHA-256", input));
    }

    /**
     * Upper-case hex SHA-1, required by the Have I Been Pwned range API.
     *
     * <p>SHA-1 is used here because the HIBP k-anonymity protocol mandates it,
     * not because it was selected as a secure hash. It is never used for
     * integrity or authentication anywhere in TrustShield. The range API also
     * requires upper-case hex specifically.
     */
    public static String sha1HexUpper(String input) {
        return toHex(digest("SHA-1", input.getBytes(StandardCharsets.UTF_8))).toUpperCase();
    }

    /**
     * Chains two hex digests into one, for the append-only integrity ledger.
     * Defined as {@code SHA-256(previousHex || currentHex)}.
     */
    public static String chain(String previousHex, String currentHex) {
        return sha256Hex(previousHex + currentHex);
    }

    private static byte[] digest(String algorithm, byte[] input) {
        try {
            return MessageDigest.getInstance(algorithm).digest(input);
        } catch (NoSuchAlgorithmException e) {
            // SHA-1 and SHA-256 are mandatory in every conformant JVM, so this
            // cannot happen in practice. Fail loudly rather than silently.
            throw new IllegalStateException(algorithm + " unavailable in this JVM", e);
        }
    }

    private static String toHex(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            out[i * 2] = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0F];
        }
        return new String(out);
    }
}
