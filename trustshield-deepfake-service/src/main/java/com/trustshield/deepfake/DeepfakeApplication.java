package com.trustshield.deepfake;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * TrustShield - Deepfake and Synthetic Media Forensics Service.
 *
 * <p>Implements six inspectable offline forensic signals:
 * <ol>
 *   <li>Error Level Analysis (ELA) via in-memory recompression and 16x16 block variance.</li>
 *   <li>JPEG Quantization Table (DQT) 0xFFDB segment parsing and table fingerprinting.</li>
 *   <li>Spatial 8x8 blockiness periodicity proxy (spatial domain proxy, not DCT-histogram).</li>
 *   <li>High-pass noise residual variance via 3x3 Laplacian filter.</li>
 *   <li>EXIF metadata provenance via Drew Noakes' metadata-extractor 2.19.0.</li>
 *   <li>C2PA / JUMBF manifest presence detection (presence only, not signature verification).</li>
 * </ol>
 *
 * <p>Enforces the honest failure invariant: recompressed media returns {@code ThreatLevel.UNKNOWN}
 * rather than falsely claiming clean provenance.
 */
@SpringBootApplication
public class DeepfakeApplication {

    public static void main(String[] args) {
        SpringApplication.run(DeepfakeApplication.class, args);
    }
}
