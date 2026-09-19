package com.trustshield.deepfake.forensics;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

/**
 * Coalition for Content Provenance and Authenticity (C2PA) manifest presence detector.
 *
 * <p><strong>CRITICAL ARCHITECTURAL NOTICE:</strong>
 * This detector performs <em>presence detection only</em>, and does <strong>NOT</strong>
 * execute full cryptographic signature validation. Detecting the presence of a C2PA manifest
 * provides important provenance context indicating the media embeds Content Authenticity
 * Initiative / JUMBF metadata boxes. Verifying full X.509 certificate chains, trust lists,
 * and manifest hash integrity is a separate, extensive public-key infrastructure operation.
 */
@Component
public class C2paManifestDetector {

    private static final Logger log = LoggerFactory.getLogger(C2paManifestDetector.class);

    // Common C2PA signatures in binary streams
    private static final byte[] C2PA_BYTES = "c2pa".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] JUMB_BYTES = "jumb".getBytes(StandardCharsets.US_ASCII);

    public record C2paResult(
            boolean detected,
            String detail
    ) {}

    /**
     * Inspects image binary data for the presence of C2PA / JUMBF manifest boxes.
     *
     * @param rawBytes image bytes
     * @return C2paResult indicating whether C2PA manifest markers were found
     */
    public C2paResult detect(byte[] rawBytes) {
        if (rawBytes == null || rawBytes.length < 16) {
            return new C2paResult(false, "Payload too small for C2PA manifest inspection");
        }

        boolean foundC2pa = indexOf(rawBytes, C2PA_BYTES) != -1;
        boolean foundJumb = indexOf(rawBytes, JUMB_BYTES) != -1;

        boolean present = foundC2pa || foundJumb;
        String detail = present
                ? "C2PA / JUMBF provenance manifest detected (Content Authenticity Initiative metadata present; presence detected, signature chain unverified)."
                : "No C2PA provenance manifest detected.";

        return new C2paResult(present, detail);
    }

    private int indexOf(byte[] source, byte[] target) {
        if (target.length == 0) {
            return 0;
        }
        for (int i = 0; i <= source.length - target.length; i++) {
            boolean match = true;
            for (int j = 0; j < target.length; j++) {
                if (source[i + j] != target[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return i;
            }
        }
        return -1;
    }
}
