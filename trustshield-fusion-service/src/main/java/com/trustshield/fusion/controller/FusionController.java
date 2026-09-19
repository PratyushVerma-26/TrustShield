package com.trustshield.fusion.controller;

import com.trustshield.common.dto.IncidentFusionRequest;
import com.trustshield.common.dto.IncidentFusionResponse;
import com.trustshield.fusion.engine.FusionRule;
import com.trustshield.fusion.entity.IncidentFusionRecord;
import com.trustshield.fusion.service.IncidentFusionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping({"/api/v1/fusion", "/api/v1/incident"})
@Tag(name = "Cross-Modal Threat Fusion", description = "Aggregates multi-vector modular indicators (phishing, deepfake, breach, fake news, ledger) into auditable incident verdicts via canonical fusion rules")
public class FusionController {

    private final IncidentFusionService service;

    public FusionController(IncidentFusionService service) {
        this.service = service;
    }

    @PostMapping(
            value = {"/evaluate", ""},
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            summary = "Evaluate cross-modal threat incident",
            description = "Applies deterministic, auditable fusion rules (R1-R5) over modular verdicts, enforcing coverage invariants and ledger tamper overrides."
    )
    public ResponseEntity<IncidentFusionResponse> evaluateIncident(@Valid @RequestBody IncidentFusionRequest request) {
        IncidentFusionResponse response = service.evaluateIncident(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping(value = "/rules", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Active fusion rules catalog", description = "Returns all registered fusion rules and their evaluation rationales.")
    public ResponseEntity<List<Map<String, String>>> rules() {
        List<Map<String, String>> ruleList = service.getActiveRules().stream()
                .map(r -> Map.of(
                        "ruleId", r.getRuleId(),
                        "ruleName", r.getRuleName(),
                        "description", r.getDescription()
                ))
                .toList();
        return ResponseEntity.ok(ruleList);
    }

    @GetMapping(value = "/history", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Recent fused incident audits", description = "Returns the 25 most recent cross-modal incident fusion evaluations.")
    public ResponseEntity<List<IncidentFusionRecord>> history() {
        return ResponseEntity.ok(service.getRecentIncidents());
    }

    @GetMapping(value = "/stats", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Threat fusion statistics", description = "Returns total evaluations, threat level distribution, and rule override counters.")
    public ResponseEntity<IncidentFusionService.FusionStats> stats() {
        return ResponseEntity.ok(service.getStats());
    }

    @GetMapping(value = "/info", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Methodology and design invariants", description = "Explains rule-based auditable fusion over black-box ML, coverage refusal invariants, and tamper overrides.")
    public ResponseEntity<Map<String, Object>> info() {
        return ResponseEntity.ok(Map.of(
                "service", "trustshield-fusion-service",
                "port", 8088,
                "paradigm", "Deterministic, auditable rule-based fusion over opaque machine learning",
                "rules", List.of(
                        "R1: Conclusive Dangerous Escalation (any conclusive DANGEROUS makes incident DANGEROUS)",
                        "R2: Multi-Modal Suspicious Escalation (2+ SUSPICIOUS across distinct modalities escalate to DANGEROUS)",
                        "R3: Coverage Invariant (any UNKNOWN or degraded modality disallows certifying SAFE)",
                        "R4: Cryptographic Ledger Override (ledger tamper detection overrides heuristic scores to DANGEROUS/95)",
                        "R5: Cross-Modal Synergistic Multiplier (co-occurrence of phishing lures with synthetic media or hoaxes)"
                ),
                "absenceOfEvidenceInvariant", "Absence of evidence is not evidence of absence. Incidents with unmeasured or degraded modalities report UNKNOWN rather than SAFE."
        ));
    }
}
