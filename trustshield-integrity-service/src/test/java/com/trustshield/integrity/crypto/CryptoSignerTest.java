package com.trustshield.integrity.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptoSignerTest {

    private CryptoSigner signer;

    @BeforeEach
    void setUp() {
        signer = new CryptoSigner();
    }

    @Test
    @DisplayName("Signer initializes with non-null Ed25519 public key in Base64 format")
    void keyInitialization() {
        assertNotNull(signer.getPublicKey());
        assertNotNull(signer.getPublicKeyBase64());
        assertFalse(signer.getPublicKeyBase64().isBlank());
    }

    @Test
    @DisplayName("Signs and verifies head chain hash using Ed25519")
    void signAndVerifyValid() {
        String data = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        String signatureHex = signer.signHex(data);

        assertNotNull(signatureHex);
        assertTrue(signatureHex.length() >= 64);

        boolean valid = signer.verifyHex(data, signatureHex);
        assertTrue(valid, "Ed25519 signature verification should succeed on genuine data");
    }

    @Test
    @DisplayName("Rejects modified data or corrupted signatures")
    void rejectsTamperedData() {
        String original = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        String tampered = "c94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

        String signatureHex = signer.signHex(original);

        assertFalse(signer.verifyHex(tampered, signatureHex), "Verification must fail on modified payload");
        assertFalse(signer.verifyHex(original, "badhex123"), "Verification must fail on corrupt hex");
        assertFalse(signer.verifyHex(original, null), "Verification must fail on null signature");
    }
}
