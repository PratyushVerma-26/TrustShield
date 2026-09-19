package com.trustshield.deepfake.service;

import com.trustshield.common.dto.DeepfakeScanRequest;
import com.trustshield.common.dto.DeepfakeScanResponse;
import com.trustshield.common.dto.IncidentId;
import com.trustshield.common.dto.ThreatLevel;
import com.trustshield.deepfake.entity.DeepfakeScanRecord;
import com.trustshield.deepfake.forensics.ImageForensicOrchestrator;
import com.trustshield.deepfake.repository.DeepfakeScanRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@Service
public class DeepfakeScanService {

    private static final Logger log = LoggerFactory.getLogger(DeepfakeScanService.class);

    private final ImageForensicOrchestrator orchestrator;
    private final DeepfakeScanRepository repository;

    public DeepfakeScanService(ImageForensicOrchestrator orchestrator, DeepfakeScanRepository repository) {
        this.orchestrator = orchestrator;
        this.repository = repository;
    }

    @Transactional
    public DeepfakeScanResponse scan(DeepfakeScanRequest request) {
        IncidentId incidentId = request.incidentId() != null ? request.incidentId() : IncidentId.generate();
        byte[] imageBytes = decodeBase64(request.imageBase64());

        return processBytes(
                incidentId,
                imageBytes,
                request.filename() != null ? request.filename() : "unnamed_image",
                request.mimeType() != null ? request.mimeType() : "application/octet-stream",
                request.context()
        );
    }

    @Transactional
    public DeepfakeScanResponse scanBytes(
            byte[] imageBytes,
            String filename,
            String mimeType,
            String context,
            IncidentId incidentId
    ) {
        IncidentId id = incidentId != null ? incidentId : IncidentId.generate();
        return processBytes(id, imageBytes, filename, mimeType, context);
    }

    private DeepfakeScanResponse processBytes(
            IncidentId incidentId,
            byte[] imageBytes,
            String filename,
            String mimeType,
            String context
    ) {
        DeepfakeScanResponse response = orchestrator.orchestrate(
                incidentId,
                imageBytes,
                filename,
                mimeType,
                context
        );

        DeepfakeScanResponse.ImageMetadata meta = response.metadata();
        DeepfakeScanResponse.ForensicSignals sig = response.forensicSignals();

        // Persist scan history in H2
        DeepfakeScanRecord record = new DeepfakeScanRecord(
                incidentId.value(),
                meta.filename(),
                meta.format(),
                meta.width(),
                meta.height(),
                meta.sizeBytes(),
                response.verdict().riskScore(),
                response.verdict().threatLevel(),
                response.verdict().verdict(),
                response.verdict().explanation(),
                sig.elaVariance(),
                sig.quantisationTableAnomalous(),
                sig.quantisationTableFingerprint(),
                sig.spatialBlockinessScore(),
                sig.noiseResidualVariance(),
                sig.metadataInconsistent(),
                sig.c2paDetected(),
                sig.recompressionDetected(),
                response.verdict().latencyMs(),
                response.verdict().degraded(),
                context,
                Instant.now()
        );

        repository.save(record);
        return response;
    }

    @Transactional(readOnly = true)
    public List<DeepfakeScanRecord> recentScans() {
        return repository.findTop25ByOrderByScannedAtDesc();
    }

    @Transactional(readOnly = true)
    public Map<String, Object> stats() {
        long total = repository.count();
        long dangerous = repository.countByThreatLevel(ThreatLevel.DANGEROUS);
        long suspicious = repository.countByThreatLevel(ThreatLevel.SUSPICIOUS);
        long unknown = repository.countByThreatLevel(ThreatLevel.UNKNOWN);
        long safe = repository.countByThreatLevel(ThreatLevel.SAFE);

        return Map.of(
                "totalScans", total,
                "dangerousCount", dangerous,
                "suspiciousCount", suspicious,
                "unknownCount", unknown,
                "safeCount", safe
        );
    }

    private byte[] decodeBase64(String raw) {
        if (raw == null || raw.isBlank()) {
            return new byte[0];
        }
        String clean = raw.trim();
        // Remove data URL prefix if present (e.g. data:image/jpeg;base64,...)
        if (clean.contains(",")) {
            clean = clean.substring(clean.indexOf(",") + 1);
        }
        // Remove whitespace / line breaks
        clean = clean.replaceAll("\\s+", "");
        try {
            return Base64.getDecoder().decode(clean);
        } catch (IllegalArgumentException e) {
            log.warn("Invalid Base64 string supplied: {}", e.getMessage());
            return new byte[0];
        }
    }
}
