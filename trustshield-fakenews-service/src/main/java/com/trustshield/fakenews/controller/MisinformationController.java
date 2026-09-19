package com.trustshield.fakenews.controller;

import com.trustshield.common.dto.ClaimCheckRequest;
import com.trustshield.common.dto.ClaimCheckResponse;
import com.trustshield.common.dto.IncidentId;
import com.trustshield.fakenews.directory.InternetFactCheckDirectoryClient;
import com.trustshield.fakenews.directory.NewsSourceCredibilityDirectory;
import com.trustshield.fakenews.entity.ClaimCheckRecord;
import com.trustshield.fakenews.service.ClaimCheckService;
import com.trustshield.fakenews.simhash.DebunkedClaimCatalog;
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
import java.util.Base64;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping({"/api/v1/misinformation", "/api/v1/fakenews"})
@Tag(name = "Misinformation & Fact Verification", description = "Multimodal claim verification via Google Fact Check API, multi-source ClaimReview directories, source credibility ratings, and capped style analysis")
public class MisinformationController {

    private final ClaimCheckService service;
    private final DebunkedClaimCatalog catalog;
    private final NewsSourceCredibilityDirectory sourceDirectory;
    private final InternetFactCheckDirectoryClient internetDirectoryClient;

    public MisinformationController(
            ClaimCheckService service,
            DebunkedClaimCatalog catalog,
            NewsSourceCredibilityDirectory sourceDirectory,
            InternetFactCheckDirectoryClient internetDirectoryClient) {
        this.service = service;
        this.catalog = catalog;
        this.sourceDirectory = sourceDirectory;
        this.internetDirectoryClient = internetDirectoryClient;
    }

    @PostMapping(
            value = {"/check", ""},
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            summary = "Verify text, image, or video claim against fact-checking directories and style markers",
            description = "Evaluates claim against Google Fact Check API, multi-source internet directories, and bundled SimHash debunked catalog. Analyzes secondary linguistic style with strict 55-point capping."
    )
    public ResponseEntity<ClaimCheckResponse> checkClaim(@Valid @RequestBody ClaimCheckRequest request) {
        ClaimCheckResponse response = service.checkClaim(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping(
            value = "/check/file",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            summary = "Verify image news or video news file directly via multipart upload",
            description = "Uploads an image or video file. Extracts visual chyrons, embedded text, metadata headlines, and evaluates against fact-checking directories."
    )
    public ResponseEntity<ClaimCheckResponse> checkMediaFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "claimText", required = false) String claimText,
            @RequestParam(value = "context", required = false) String context
    ) throws IOException {
        byte[] bytes = file.getBytes();
        String base64 = Base64.getEncoder().encodeToString(bytes);

        ClaimCheckRequest request = new ClaimCheckRequest(
                IncidentId.generate(),
                claimText,
                context != null ? context : "MEDIA_UPLOAD",
                null, // will be auto-detected from filename/mime
                base64,
                file.getOriginalFilename(),
                file.getContentType()
        );

        ClaimCheckResponse response = service.checkClaim(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping(value = "/history", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Recent claim checks", description = "Returns the 25 most recent claim verification audits.")
    public ResponseEntity<List<ClaimCheckRecord>> history() {
        return ResponseEntity.ok(service.getRecentChecks());
    }

    @GetMapping(value = "/stats", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Misinformation verification statistics", description = "Returns total checks, debunk match rates, threat level distribution, and engine status.")
    public ResponseEntity<ClaimCheckService.MisinformationStats> stats() {
        return ResponseEntity.ok(service.getStats());
    }

    @GetMapping(value = "/claims", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Bundled debunked claims catalog", description = "Exposes the offline curated catalog of known viral hoaxes and fact-check sources.")
    public ResponseEntity<List<DebunkedClaimCatalog.CatalogEntry>> claims() {
        return ResponseEntity.ok(catalog.getEntries());
    }

    @GetMapping(value = "/directories", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Connected fact-check directories and source credibility catalog", description = "Exposes status of connected internet directories and known source catalogs.")
    public ResponseEntity<Map<String, Object>> directories() {
        return ResponseEntity.ok(Map.of(
                "internetDirectoryEnabled", internetDirectoryClient.isEnabled(),
                "bundledDebunkDirectoryCount", internetDirectoryClient.getBundledEntryCount(),
                "knownNewsSourceCount", sourceDirectory.getSourceCount(),
                "simHashCatalogCount", catalog.getEntryCount()
        ));
    }

    @GetMapping(value = "/info", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Methodology and design invariants", description = "Explains evidence weighting inversion, style capping invariant, and multimodal features.")
    public ResponseEntity<Map<String, Object>> info() {
        return ResponseEntity.ok(Map.of(
                "service", "trustshield-fakenews-service",
                "port", 8086,
                "modalitiesSupported", List.of("TEXT", "IMAGE_NEWS", "VIDEO_NEWS"),
                "features", List.of(
                        "Multimodal headline extraction from IPTC/EXIF/XMP metadata",
                        "Lower-third news chyron visual detection & font step discontinuity analysis",
                        "Video container metadata and keyframe stream parsing",
                        "Curated news publisher credibility evaluation (Mainstream, Satire, Disinformation)",
                        "Multi-source ClaimReview internet directory client with offline debunk fallback",
                        "64-bit locality-sensitive SimHash near-duplicate matching",
                        "Linguistic style analysis with 55-point maximum ceiling"
                ),
                "evidenceWeighting", "Inverted: external fact-check corroboration is primary; linguistic style is secondary correlation",
                "styleCappingInvariant", "Linguistic style score is hard-capped at 55 and can NEVER escalate a claim to DANGEROUS on its own",
                "truthCertitudeRefusal", "TrustShield cannot establish that an unindexed claim is true or false. Unchecked claims return UNKNOWN rather than SAFE"
        ));
    }
}
