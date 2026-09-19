package com.trustshield.integrity.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HashChainCalculatorTest {

    @Test
    @DisplayName("Genesis hash is exactly 64 zeros")
    void genesisHashFormat() {
        assertEquals(64, HashChainCalculator.GENESIS_HASH.length());
        assertTrue(HashChainCalculator.GENESIS_HASH.matches("0{64}"));
    }

    @Test
    @DisplayName("sha256Hex produces lowercase 64-character hex string")
    void sha256HexFormat() {
        String hash = HashChainCalculator.sha256Hex("hello world");
        assertNotNull(hash);
        assertEquals(64, hash.length());
        assertEquals("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", hash);
    }

    @Test
    @DisplayName("Chain hash calculation chains previous chain hash and entry hash")
    void chainHashCalculation() {
        String entry = HashChainCalculator.calculateEntryHash("{\"verdict\":\"SAFE\"}");
        String chain0 = HashChainCalculator.calculateChainHash(HashChainCalculator.GENESIS_HASH, entry);

        assertEquals(64, entry.length());
        assertEquals(64, chain0.length());

        String nextEntry = HashChainCalculator.calculateEntryHash("{\"verdict\":\"DANGEROUS\"}");
        String chain1 = HashChainCalculator.calculateChainHash(chain0, nextEntry);

        assertEquals(64, chain1.length());
        assertFalse(chain0.equals(chain1));
    }

    @Test
    @DisplayName("constantTimeEquals performs case-insensitive constant-time equality")
    void constantTimeEquals() {
        String h1 = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        String h2 = "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9";
        String h3 = "0000000000000000000000000000000000000000000000000000000000000000";

        assertTrue(HashChainCalculator.constantTimeEquals(h1, h2));
        assertFalse(HashChainCalculator.constantTimeEquals(h1, h3));
        assertFalse(HashChainCalculator.constantTimeEquals(h1, null));
    }
}
