package com.trustshield.integrity.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Asymmetric Ed25519 cryptographic signer for cumulative ledger head hashes.
 *
 * <p><strong>Viva Defense & Security Rationale:</strong>
 * A hash chain inside a database is tamper-evident against an adversary with application access,
 * but <em>not</em> against an adversary with full database write privileges (who could recompute
 * the chain). By digitally signing the head chain hash with an Ed25519 private key stored outside
 * the database, the server ensures non-repudiation: database rows cannot be altered or recomputed
 * without invalidating the external digital signature.
 */
@Component
public class CryptoSigner {

    private static final Logger log = LoggerFactory.getLogger(CryptoSigner.class);
    private static final HexFormat HEX = HexFormat.of();

    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final String publicKeyBase64;

    public CryptoSigner() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
            KeyPair keyPair = kpg.generateKeyPair();
            this.privateKey = keyPair.getPrivate();
            this.publicKey = keyPair.getPublic();
            this.publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            log.info("Initialized Ed25519 CryptoSigner with public key: {}", publicKeyBase64);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Ed25519 signature algorithm not supported on this JDK", e);
        }
    }

    public CryptoSigner(KeyPair keyPair) {
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
        this.publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     * Signs the input string using Ed25519 and returns the signature as a hex string.
     */
    public String signHex(String data) {
        if (data == null) {
            throw new IllegalArgumentException("Data to sign cannot be null");
        }
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(privateKey);
            sig.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = sig.sign();
            return HEX.formatHex(signatureBytes);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign data with Ed25519", e);
        }
    }

    /**
     * Verifies the Ed25519 hex signature of the given data using the public key.
     */
    public boolean verifyHex(String data, String signatureHex) {
        if (data == null || signatureHex == null || signatureHex.isBlank()) {
            return false;
        }
        try {
            byte[] sigBytes = HEX.parseHex(signatureHex);
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(publicKey);
            sig.update(data.getBytes(StandardCharsets.UTF_8));
            return sig.verify(sigBytes);
        } catch (Exception e) {
            log.warn("Ed25519 signature verification failed with error: {}", e.getMessage());
            return false;
        }
    }

    public String getPublicKeyBase64() {
        return publicKeyBase64;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
