package com.trustshield.breach.hibp;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.trustshield.breach.config.BreachProperties;
import com.trustshield.common.util.HashUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the k-anonymity range protocol.
 *
 * <p>{@code findSuffix} is pure string handling, so it can be tested exhaustively
 * with no network. Three of the cases below correspond to real ways this could go
 * wrong, each with a different consequence: padding read as a hit would report
 * <em>every</em> password as breached; a prefix match would report the wrong
 * password as breached; and a failed lookup read as clean would report a breached
 * password as safe.
 */
class PwnedPasswordsClientTest {

    /**
     * SHA-1 of {@code P@ssw0rd}, which is the example used in the Pwned Passwords
     * API documentation. Splitting it 5 + 35 gives prefix {@code 21BD1}.
     */
    private static final String PASSWORD = "P@ssw0rd";
    private static final String FULL_HASH = "21BD12DC183F740EE76F27B78EB39C8AD972A757";
    private static final String SUFFIX = "2DC183F740EE76F27B78EB39C8AD972A757";

    private static PwnedPasswordsClient disabledClient() {
        // Every field null/zero: the record's canonical constructor supplies the
        // defaults, which include pwned-passwords being disabled.
        return new PwnedPasswordsClient(new BreachProperties(null, 0L, null, null));
    }

    @Test
    @DisplayName("the hash splits 5 + 35, and only the 5 would ever be sent")
    void protocolSplit() {
        String hash = HashUtils.sha1HexUpper(PASSWORD);
        assertEquals(FULL_HASH, hash, "SHA-1 of the documented example password");
        assertEquals(40, hash.length());
        assertEquals("21BD1", hash.substring(0, 5), "the only part the server sees");
        assertEquals(SUFFIX, hash.substring(5));
        assertEquals(35, hash.substring(5).length(), "matched locally, never transmitted");
    }

    @Test
    @DisplayName("a matching suffix returns its occurrence count")
    void findsMatchingSuffix() {
        String body = """
                0018A45C4D1DEF81644B54AB7F969B88D65:1
                00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2
                2DC183F740EE76F27B78EB39C8AD972A757:83
                011053FD0102E94D6AE2F8B83D76FAF94F6:7
                """;
        assertEquals(83L, PwnedPasswordsClient.findSuffix(body, SUFFIX));
    }

    @Test
    @DisplayName("an absent suffix returns zero")
    void absentSuffix() {
        String body = """
                0018A45C4D1DEF81644B54AB7F969B88D65:1
                00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2
                """;
        assertEquals(0L, PwnedPasswordsClient.findSuffix(body, SUFFIX));
    }

    /**
     * The padding case, which is the one with the widest blast radius.
     *
     * <p>{@code Add-Padding: true} makes the API return extra entries whose count
     * is zero, so that response size does not reveal the queried bucket. Those
     * entries are indistinguishable from real ones except by their count. Reading
     * a zero as a hit would mark every single password as breached — the service
     * would appear to work perfectly while being entirely wrong.
     */
    @Test
    @DisplayName("a zero count is padding, not a match")
    void zeroCountIsPaddingNotAMatch() {
        String body = """
                0018A45C4D1DEF81644B54AB7F969B88D65:1
                2DC183F740EE76F27B78EB39C8AD972A757:0
                011053FD0102E94D6AE2F8B83D76FAF94F6:5
                """;
        assertEquals(0L, PwnedPasswordsClient.findSuffix(body, SUFFIX),
                "a padding entry must not be reported as an occurrence");
    }

    @Test
    @DisplayName("suffix comparison is case-insensitive but full-length")
    void caseInsensitiveFullLengthMatch() {
        String lowerCaseBody = "2dc183f740ee76f27b78eb39c8ad972a757:11\n";
        assertEquals(11L, PwnedPasswordsClient.findSuffix(lowerCaseBody, SUFFIX));

        // A partial match must NOT count. Suffixes in one bucket share no prefix
        // guarantee, so accepting a prefix would attribute another password's
        // count to this one.
        assertEquals(0L, PwnedPasswordsClient.findSuffix(lowerCaseBody, "2DC183"));
    }

    @Test
    @DisplayName("CRLF line endings and malformed lines are handled")
    void toleratesRealWorldResponses() {
        // HIBP returns CRLF. A stray blank or colon-less line must be skipped
        // rather than throwing, because a parse failure here would be reported as
        // "not found" — the wrong direction to fail in.
        String body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n"
                + "garbage-with-no-colon\r\n"
                + "\r\n"
                + ":42\r\n"
                + SUFFIX + ":9\r\n";
        assertEquals(9L, PwnedPasswordsClient.findSuffix(body, SUFFIX));
    }

    @Test
    @DisplayName("a non-numeric count is treated as no match, not as an error")
    void nonNumericCount() {
        assertEquals(0L, PwnedPasswordsClient.findSuffix(SUFFIX + ":not-a-number\n", SUFFIX));
    }

    @Test
    @DisplayName("disabled by default, and disabled means UNAVAILABLE not NOT_FOUND")
    void disabledYieldsUnavailable() {
        PwnedPasswordsClient client = disabledClient();
        assertFalse(client.isEnabled(), "network lookups must be opt-in for a demo-safe default");

        BreachLookupResult result = client.check(PASSWORD);
        assertEquals(BreachLookupResult.Status.UNAVAILABLE, result.status(),
                "reporting NOT_FOUND here would tell a user a breached password is clean");
        assertTrue(result.isUnavailable());
        assertFalse(result.isExposed());
        assertTrue(result.occurrences().isEmpty(), "no count may be invented");
        assertEquals(PwnedPasswordsClient.SOURCE, result.source());
    }

    @Test
    @DisplayName("an empty password is unavailable rather than silently checked")
    void emptyPassword() {
        assertEquals(BreachLookupResult.Status.UNAVAILABLE,
                disabledClient().check("").status());
    }

    @Test
    @DisplayName("padding defaults to on")
    void paddingDefaultsOn() {
        // Without padding, response size leaks which bucket was queried, which
        // partially defeats the point of the protocol. There is no reason to
        // disable it, so the default must not be false.
        BreachProperties props = new BreachProperties(null, 0L, null, null);
        assertTrue(props.pwnedPasswords().addPadding());
        assertEquals("https://api.pwnedpasswords.com", props.pwnedPasswords().baseUrl());
    }
}
