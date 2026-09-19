package com.trustshield.deepfake.controller;

import com.trustshield.common.dto.DeepfakeScanRequest;
import com.trustshield.common.dto.DeepfakeScanResponse;
import com.trustshield.common.dto.IncidentId;
import com.trustshield.deepfake.entity.DeepfakeScanRecord;
import com.trustshield.deepfake.service.DeepfakeScanService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/deepfake")
@Tag(name = "Deepfake & Synthetic Media Detector", description = "Offline classical forensics for image manipulation and synthetic media detection")
public class DeepfakeController {

    private final DeepfakeScanService service;

    public DeepfakeController(DeepfakeScanService service) {
        this.service = service;
    }

    @PostMapping(value = "/scan", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Forensic scan of Base64 encoded image", description = "Executes six offline forensic checks: ELA, DQT 0xFFDB table fingerprinting, 8x8 spatial blockiness proxy, noise residual variance, EXIF provenance, and C2PA manifest detection.")
    public ResponseEntity<DeepfakeScanResponse> scan(@Valid @RequestBody DeepfakeScanRequest request) {
        DeepfakeScanResponse response = service.scan(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping(value = "/scan/file", consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Forensic scan of uploaded image file", description = "Direct multipart file upload endpoint for testing and direct browser submission.")
    public ResponseEntity<DeepfakeScanResponse> scanFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "context", required = false) String context,
            @RequestParam(value = "incidentId", required = false) String incidentIdStr
    ) throws IOException {
        IncidentId incidentId = (incidentIdStr != null && !incidentIdStr.isBlank())
                ? new IncidentId(incidentIdStr)
                : IncidentId.generate();

        DeepfakeScanResponse response = service.scanBytes(
                file.getBytes(),
                file.getOriginalFilename(),
                file.getContentType(),
                context,
                incidentId
        );
        return ResponseEntity.ok(response);
    }

    @GetMapping(value = "/history", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Recent forensic scan history", description = "Returns the 25 most recent image forensic scans recorded in the local store.")
    public ResponseEntity<List<DeepfakeScanRecord>> history() {
        return ResponseEntity.ok(service.recentScans());
    }

    @GetMapping(value = "/stats", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Forensic detection statistics", description = "Aggregated count of scans categorized by threat level.")
    public ResponseEntity<Map<String, Object>> stats() {
        return ResponseEntity.ok(service.stats());
    }

    @GetMapping(value = "/forensics/info", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Forensic signals and limitation disclosure", description = "Explains the six offline signals and provides honest disclosure regarding classical forensics limitations.")
    public ResponseEntity<Map<String, Object>> forensicsInfo() {
        return ResponseEntity.ok(Map.of(
                "module", "trustshield-deepfake-service",
                "port", 8085,
                "supportedMedia", List.of("IMAGE", "VIDEO", "AUDIO"),
                "signals", List.of(
                        Map.of("name", "Error Level Analysis (ELA)", "technique", "In-memory JPEG recompression at 90% quality and 16x16 block-wise variance measurement."),
                        Map.of("name", "JPEG Quantization Fingerprinting", "technique", "Direct 0xFFDB DQT segment parsing, SHA-256 fingerprinting, and flat/anomalous table detection."),
                        Map.of("name", "Spatial 8x8 Blockiness Periodicity", "technique", "Spatial proxy ratio evaluating boundary step gradients versus intra-block gradients. Notice: Not DCT-histogram detection."),
                        Map.of("name", "Noise Residual Variance", "technique", "High-pass 3x3 Laplacian filtering measuring sensor pattern noise consistency and synthetic hyper-smoothness."),
                        Map.of("name", "EXIF Metadata Provenance", "technique", "Drew Noakes metadata-extractor 2.19.0 parsing camera make/model and software tags for manipulation signatures."),
                        Map.of("name", "C2PA Manifest Detection", "technique", "Presence detection of JUMBF/c2pa manifest boxes in APP11 markers. Notice: Presence detection only, not cryptographic signature validation."),
                        Map.of("name", "Video Temporal Consistency & Jitter", "technique", "ISO BMFF / MP4 container box parsing and keyframe inter-frame noise residual divergence measurement detecting face-swap boundary flickering."),
                        Map.of("name", "Multilingual Audio Voice Clone Forensics", "technique", "Acoustic signal analysis detecting neural vocoder spectral roll-off cutoffs, robotic pitch micro-tremors, and digital zero silence biophysics across multiple spoken languages."),
                        Map.of("name", "Internet Media Verification Directory", "technique", "Cross-checks media SHA-256 against C2PA trust registries and known debunked synthetic media catalogs.")
                ),
                "honestLimitations", Map.of(
                        "recompressionHandling", "Lossy recompression or downscaling (e.g. WhatsApp photos) destroys forensic traces; honest verdict returned is UNKNOWN.",
                        "generativeAiCaveat", "Classical forensics inspects physical compression and camera sensor traces; it cannot reliably detect modern generative AI outputs that synthesize uniform pixel statistics."
                )
        ));
    }
}
