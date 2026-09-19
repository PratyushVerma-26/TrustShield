package com.trustshield.phishing.controller;

import com.trustshield.phishing.dto.ScanHistoryItem;
import com.trustshield.phishing.dto.ScanRequest;
import com.trustshield.phishing.dto.ScanResponse;
import com.trustshield.phishing.ml.PhishingModel;
import com.trustshield.phishing.ml.UrlFeatureExtractor;
import com.trustshield.phishing.service.UrlScanService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/phishing")
@Tag(name = "Phishing Detection",
        description = "Lexical URL classification with optional external corroboration")
public class PhishingController {

    private final UrlScanService scanService;
    private final PhishingModel model;

    public PhishingController(UrlScanService scanService, PhishingModel model) {
        this.scanService = scanService;
        this.model = model;
    }

    @PostMapping("/scan")
    @Operation(summary = "Scan a URL",
            description = "Returns a risk score of 0-100, a threat level, and the "
                    + "signals that produced them. Always answers: if external "
                    + "reputation sources are unavailable the verdict is returned "
                    + "from the local model and flagged as degraded.")
    public ResponseEntity<ScanResponse> scan(@Valid @RequestBody ScanRequest request) {
        return ResponseEntity.ok(scanService.scan(request));
    }

    @GetMapping("/history")
    @Operation(summary = "Recent scans", description = "The 25 most recent assessments.")
    public ResponseEntity<List<ScanHistoryItem>> history() {
        return ResponseEntity.ok(scanService.recentScans());
    }

    @GetMapping("/stats")
    @Operation(summary = "Dashboard counters")
    public ResponseEntity<Map<String, Object>> stats() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("totalScans", scanService.totalScans());
        body.put("dangerousScans", scanService.countDangerous());
        body.put("modelVersion", model.getModelVersion());
        body.put("modelProvenance", model.getProvenance());
        body.put("modelTrained", model.isTrained());
        return ResponseEntity.ok(body);
    }

    @GetMapping("/model")
    @Operation(summary = "Model card",
            description = "Model identity, feature list, and metadata indicating "
                    + "whether loaded weights were trained on real data.")
    public ResponseEntity<Map<String, Object>> modelCard() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("version", model.getModelVersion());
        body.put("provenance", model.getProvenance());
        body.put("trained", model.isTrained());
        body.put("algorithm", "Logistic regression on standardised lexical features");
        body.put("featureCount", UrlFeatureExtractor.FEATURE_COUNT);
        body.put("features", List.of(UrlFeatureExtractor.FEATURE_NAMES));
        body.put("explainability",
                "Per-feature contribution is w_i * z_i, which is exact for a linear "
                        + "model rather than a post-hoc approximation.");
        if (!model.isTrained()) {
            body.put("warning",
                    "These weights are a hand-initialised bootstrap. Accuracy, precision, "
                            + "recall and F1 must not be reported against this model.");
        }
        return ResponseEntity.ok(body);
    }
}
