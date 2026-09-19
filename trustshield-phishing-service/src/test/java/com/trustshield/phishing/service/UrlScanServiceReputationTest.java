package com.trustshield.phishing.service;

import com.trustshield.common.dto.ThreatLevel;
import com.trustshield.phishing.dto.ScanRequest;
import com.trustshield.phishing.dto.ScanResponse;
import com.trustshield.phishing.entity.ScanRecord;
import com.trustshield.phishing.ml.ModelPrediction;
import com.trustshield.phishing.ml.PhishingModel;
import com.trustshield.phishing.repository.ScanRecordRepository;
import com.trustshield.phishing.reputation.ReputationSource;
import com.trustshield.phishing.reputation.ReputationVerdict;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UrlScanServiceReputationTest {

    @Mock
    private PhishingModel model;

    @Mock
    private ScanRecordRepository repository;

    @Mock
    private ReputationSource googleSafeBrowsing;

    @Mock
    private ReputationSource virusTotal;

    private UrlScanService service;

    @BeforeEach
    void setUp() {
        service = new UrlScanService(model, List.of(googleSafeBrowsing, virusTotal), repository);
        ReflectionTestUtils.setField(service, "blacklistConfirmedFloor", 90);
        ReflectionTestUtils.setField(service, "enrichmentTimeoutMs", 1200L);

        when(googleSafeBrowsing.name()).thenReturn("GOOGLE_SAFE_BROWSING");
        when(googleSafeBrowsing.isEnabled()).thenReturn(true);
        when(virusTotal.name()).thenReturn("VIRUSTOTAL");
        when(virusTotal.isEnabled()).thenReturn(true);

        when(repository.save(any(ScanRecord.class))).thenAnswer(inv -> {
            ScanRecord rec = inv.getArgument(0);
            return new ScanRecord(
                    rec.getUrl(), rec.getUrlHash(), rec.getHost(), rec.getRiskScore(),
                    rec.getThreatLevel(), rec.getVerdict(), rec.getExplanation(),
                    rec.getLatencyMs(), rec.isDegraded(), rec.getModelVersion(),
                    rec.getModelProvenance(), rec.getSourceContext(), Instant.now()
            );
        });
    }

    @Test
    @DisplayName("Safe Browsing match floors the score at 90 (DANGEROUS)")
    void safeBrowsingMatchFloorsScoreAt90() {
        when(model.predict(anyString())).thenReturn(new ModelPrediction(
                0.20, -1.38, new double[26], new double[26]
        ));
        when(model.isTrained()).thenReturn(true);
        when(model.getModelVersion()).thenReturn("1.0.0");
        when(model.getProvenance()).thenReturn("TRAINED");

        when(googleSafeBrowsing.check(anyString())).thenReturn(
                ReputationVerdict.flagged("GOOGLE_SAFE_BROWSING", 100, "Safe Browsing match: MALWARE")
        );
        when(virusTotal.check(anyString())).thenReturn(
                ReputationVerdict.clean("VIRUSTOTAL", 0, "No VirusTotal match")
        );

        ScanResponse response = service.scan(new ScanRequest("https://malicious-test.example", "WEB"));

        assertThat(response.verdict().riskScore()).isGreaterThanOrEqualTo(90);
        assertThat(response.verdict().threatLevel()).isEqualTo(ThreatLevel.DANGEROUS);
        assertThat(response.verdict().signals())
                .anyMatch(s -> s.name().equals("GOOGLE_SAFE_BROWSING_MATCH") && s.triggered());
    }

    @Test
    @DisplayName("Reputation sources cannot lower score (raise-only invariant)")
    void reputationSourcesCannotLowerScore() {
        when(model.predict(anyString())).thenReturn(new ModelPrediction(
                0.75, 1.1, new double[26], new double[26]
        ));
        when(model.isTrained()).thenReturn(true);
        when(model.getModelVersion()).thenReturn("1.0.0");
        when(model.getProvenance()).thenReturn("TRAINED");

        when(googleSafeBrowsing.check(anyString())).thenReturn(
                ReputationVerdict.clean("GOOGLE_SAFE_BROWSING", 0, "No Safe Browsing match")
        );
        when(virusTotal.check(anyString())).thenReturn(
                ReputationVerdict.clean("VIRUSTOTAL", 0, "No VirusTotal match")
        );

        ScanResponse response = service.scan(new ScanRequest("https://suspicious-test.example", "WEB"));

        assertThat(response.verdict().riskScore()).isEqualTo(75);
        assertThat(response.verdict().threatLevel()).isEqualTo(ThreatLevel.DANGEROUS);
    }
}
