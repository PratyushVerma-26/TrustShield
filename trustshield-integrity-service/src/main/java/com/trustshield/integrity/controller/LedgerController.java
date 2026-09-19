package com.trustshield.integrity.controller;

import com.trustshield.common.dto.LedgerAppendRequest;
import com.trustshield.common.dto.LedgerEntry;
import com.trustshield.common.dto.LedgerHeadResponse;
import com.trustshield.common.dto.LedgerVerifyResponse;
import com.trustshield.integrity.crypto.HashChainCalculator;
import com.trustshield.integrity.service.IntegrityLedgerService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping({"/api/v1/integrity", "/api/v1/ledger"})
@Tag(name = "Cryptographic Integrity Ledger", description = "Append-only SHA-256 hash-chained audit ledger with Ed25519 digital signatures")
public class LedgerController {

    private final IntegrityLedgerService service;

    public LedgerController(IntegrityLedgerService service) {
        this.service = service;
    }

    @PostMapping(value = "/append", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Commit a verdict or incident to the append-only ledger",
            description = "Computes SHA-256 entry hash, links to cumulative chain hash, and signs head with Ed25519.")
    public ResponseEntity<LedgerEntry> append(@Valid @RequestBody LedgerAppendRequest request) {
        LedgerEntry entry = service.append(request);
        return ResponseEntity.ok(entry);
    }

    @GetMapping(value = "/head", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Query latest head hash and digital signature",
            description = "Returns current sequence number, head chain hash, Ed25519 signature hex, and public key.")
    public ResponseEntity<LedgerHeadResponse> head() {
        return ResponseEntity.ok(service.getHead());
    }

    @GetMapping(value = "/verify", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Audit hash chain integrity",
            description = "Traverses all chain links from genesis. If broken, identifies the first corrupted index and reports subsequent entries as unverifiable.")
    public ResponseEntity<LedgerVerifyResponse> verifyGet() {
        return ResponseEntity.ok(service.verifyLedger());
    }

    @PostMapping(value = "/verify", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Audit hash chain integrity (POST)",
            description = "Audit endpoint supporting POST requests from administrative or automated monitors.")
    public ResponseEntity<LedgerVerifyResponse> verifyPost() {
        return ResponseEntity.ok(service.verifyLedger());
    }

    @GetMapping(value = "/entry/{seq}", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Retrieve specific ledger entry by sequence number",
            description = "Returns full cryptographic metadata and canonical payload for sequence number.")
    public ResponseEntity<LedgerEntry> getEntry(@PathVariable("seq") long sequenceNumber) {
        return service.getEntry(sequenceNumber)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping(value = "/entries", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Retrieve recent ledger entries",
            description = "Returns the 50 most recent committed audit entries in descending order.")
    public ResponseEntity<List<LedgerEntry>> getEntries() {
        return ResponseEntity.ok(service.getRecentEntries());
    }

    @GetMapping(value = "/info", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Ledger cryptographic architecture and viva defense rationale",
            description = "Explains why linear SHA-256 chaining + Ed25519 was chosen over blockchain consensus overhead.")
    public ResponseEntity<Map<String, Object>> info() {
        LedgerHeadResponse head = service.getHead();
        return ResponseEntity.ok(Map.of(
                "service", "trustshield-integrity-service",
                "port", 8087,
                "hashingFormula", "entryHash = SHA-256(canonicalPayload); chainHash = SHA-256(previousChainHash + entryHash)",
                "genesisHash", HashChainCalculator.GENESIS_HASH,
                "signatureScheme", "Ed25519 asymmetric digital signatures on cumulative head hash",
                "tamperEvidenceGuarantee", "Adversary modifying database cannot forge valid Ed25519 signature on recomputed head without private key",
                "unverifiableVsWrong", "When a link breaks at index k, all subsequent entries (> k) are unverifiable rather than wrong",
                "currentSequenceNumber", head.sequenceNumber(),
                "headChainHash", head.headChainHash(),
                "publicKeyBase64", head.publicKeyBase64()
        ));
    }
}
