package com.trustshield.integrity.service;

import com.trustshield.common.dto.IncidentId;
import com.trustshield.common.dto.LedgerAppendRequest;
import com.trustshield.common.dto.LedgerEntry;
import com.trustshield.common.dto.LedgerHeadResponse;
import com.trustshield.common.dto.LedgerVerifyResponse;
import com.trustshield.common.dto.ModuleType;
import com.trustshield.integrity.crypto.CryptoSigner;
import com.trustshield.integrity.crypto.HashChainCalculator;
import com.trustshield.integrity.entity.LedgerEntryRecord;
import com.trustshield.integrity.repository.LedgerEntryRecordRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
class IntegrityLedgerServiceTest {

    @Autowired
    private IntegrityLedgerService service;

    @Autowired
    private LedgerEntryRecordRepository repository;

    @Autowired
    private CryptoSigner cryptoSigner;

    @org.junit.jupiter.api.BeforeEach
    void setUp() {
        repository.deleteAll();
    }

    @Test
    @DisplayName("Empty ledger returns sequence -1 with genesis hash and valid Ed25519 signature")
    void emptyLedgerHead() {
        LedgerHeadResponse head = service.getHead();
        assertEquals(-1L, head.sequenceNumber());
        assertEquals(HashChainCalculator.GENESIS_HASH, head.headChainHash());
        assertNotNull(head.ed25519SignatureHex());

        boolean sigValid = cryptoSigner.verifyHex(HashChainCalculator.GENESIS_HASH, head.ed25519SignatureHex());
        assertTrue(sigValid);
    }

    @Test
    @DisplayName("Sequential appends produce monotonic sequence numbers and valid SHA-256 chain links")
    void sequentialAppends() {
        LedgerEntry e0 = service.append(new LedgerAppendRequest(
                IncidentId.generate(), ModuleType.PHISHING, "{\"url\":\"http://safe.com\",\"score\":5}"));
        assertEquals(0L, e0.sequenceNumber());
        assertEquals(HashChainCalculator.GENESIS_HASH, e0.previousChainHash());

        LedgerEntry e1 = service.append(new LedgerAppendRequest(
                IncidentId.generate(), ModuleType.DEEPFAKE, "{\"image\":\"face.jpg\",\"score\":88}"));
        assertEquals(1L, e1.sequenceNumber());
        assertEquals(e0.chainHash(), e1.previousChainHash());

        LedgerEntry e2 = service.append(new LedgerAppendRequest(
                IncidentId.generate(), ModuleType.FAKENEWS, "{\"claim\":\"moon hoax\",\"score\":90}"));
        assertEquals(2L, e2.sequenceNumber());
        assertEquals(e1.chainHash(), e2.previousChainHash());

        // Verify full intact chain
        LedgerVerifyResponse verify = service.verifyLedger();
        assertTrue(verify.valid());
        assertEquals(3L, verify.totalEntriesChecked());
        assertEquals(e2.chainHash(), verify.headChainHash());
        assertTrue(verify.signatureValid());
    }

    @Test
    @DisplayName("Crucial Invariant: Database payload tampering breaks chain and names first corrupted index")
    void tamperDetectionPinpointsFirstBadIndex() {
        // Append 3 genuine entries
        service.append(new LedgerAppendRequest(
                IncidentId.generate(), ModuleType.PHISHING, "{\"event\":\"login-1\"}"));
        LedgerEntry e1 = service.append(new LedgerAppendRequest(
                IncidentId.generate(), ModuleType.BREACH, "{\"event\":\"breach-2\"}"));
        service.append(new LedgerAppendRequest(
                IncidentId.generate(), ModuleType.FAKENEWS, "{\"event\":\"news-3\"}"));

        // Verify clean initially
        assertTrue(service.verifyLedger().valid());

        // Tamper directly with the database row at sequence 1 (e.g. adversary altered the JSON payload)
        LedgerEntryRecord record1 = repository.findBySequenceNumber(1L).orElseThrow();
        record1.setCanonicalPayload("{\"event\":\"breach-2-TAMPERED-BY-ADVERSARY\"}");
        repository.save(record1);

        // Run verification: must detect tampering at sequence 1
        LedgerVerifyResponse verify = service.verifyLedger();
        assertFalse(verify.valid(), "Verification must fail on tampered ledger");
        assertEquals(1L, verify.firstCorruptedIndex());
        assertNotNull(verify.failureReason());
        assertTrue(verify.failureReason().contains("sequence 1"));
        assertTrue(verify.failureReason().contains("unverifiable"));
    }
}
