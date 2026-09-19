package com.trustshield.integrity.service;

import com.trustshield.common.dto.IncidentId;
import com.trustshield.common.dto.LedgerAppendRequest;
import com.trustshield.common.dto.LedgerEntry;
import com.trustshield.common.dto.LedgerHeadResponse;
import com.trustshield.common.dto.LedgerVerifyResponse;
import com.trustshield.integrity.crypto.CryptoSigner;
import com.trustshield.integrity.crypto.HashChainCalculator;
import com.trustshield.integrity.entity.LedgerEntryRecord;
import com.trustshield.integrity.repository.LedgerEntryRecordRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Service managing append-only cryptographic hash chaining, Ed25519 digital signatures,
 * and live tamper verification.
 *
 * <p><strong>Core Invariants:</strong>
 * <ul>
 *   <li>Sequential append is strictly monotonic and thread-safe.</li>
 *   <li>Chain hash formula: {@code chainHash = SHA-256(previousChainHash + entryHash)}.</li>
 *   <li>Genesis entry links to 64 zeros: {@value HashChainCalculator#GENESIS_HASH}.</li>
 *   <li>Head chain hash is digitally signed with an Ed25519 private key.</li>
 *   <li>When tampering breaks the chain, {@link #verifyLedger()} reports the exact
 *       first broken index and notes that all subsequent entries are <em>unverifiable
 *       rather than merely wrong</em>.</li>
 * </ul>
 */
@Service
public class IntegrityLedgerService {

    private static final Logger log = LoggerFactory.getLogger(IntegrityLedgerService.class);

    private final LedgerEntryRecordRepository repository;
    private final CryptoSigner cryptoSigner;

    public IntegrityLedgerService(LedgerEntryRecordRepository repository, CryptoSigner cryptoSigner) {
        this.repository = repository;
        this.cryptoSigner = cryptoSigner;
    }

    /**
     * Appends a new canonical verdict or incident payload to the cryptographic hash chain.
     */
    @Transactional
    public synchronized LedgerEntry append(LedgerAppendRequest request) {
        Optional<LedgerEntryRecord> latestOpt = repository.findTopByOrderBySequenceNumberDesc();

        long nextSequence;
        String previousChainHash;

        if (latestOpt.isPresent()) {
            LedgerEntryRecord latest = latestOpt.get();
            nextSequence = latest.getSequenceNumber() + 1;
            previousChainHash = latest.getChainHash();
        } else {
            nextSequence = 0L;
            previousChainHash = HashChainCalculator.GENESIS_HASH;
        }

        String entryHash = HashChainCalculator.calculateEntryHash(request.canonicalVerdictJson());
        String chainHash = HashChainCalculator.calculateChainHash(previousChainHash, entryHash);
        Instant now = Instant.now();

        LedgerEntryRecord record = new LedgerEntryRecord(
                nextSequence,
                request.incidentId().value(),
                request.module(),
                entryHash,
                previousChainHash,
                chainHash,
                request.canonicalVerdictJson(),
                now
        );

        LedgerEntryRecord saved = repository.save(record);
        log.info("Committed ledger entry seq={}, incidentId={}, module={}, chainHash={}",
                nextSequence, request.incidentId().value(), request.module(), chainHash);

        return toDto(saved);
    }

    /**
     * Returns the current head state of the ledger, including the Ed25519 signature of the head hash.
     */
    @Transactional(readOnly = true)
    public LedgerHeadResponse getHead() {
        Optional<LedgerEntryRecord> latestOpt = repository.findTopByOrderBySequenceNumberDesc();

        if (latestOpt.isEmpty()) {
            String genesisSig = cryptoSigner.signHex(HashChainCalculator.GENESIS_HASH);
            return new LedgerHeadResponse(
                    -1L,
                    HashChainCalculator.GENESIS_HASH,
                    genesisSig,
                    cryptoSigner.getPublicKeyBase64(),
                    Instant.now()
            );
        }

        LedgerEntryRecord latest = latestOpt.get();
        String signatureHex = cryptoSigner.signHex(latest.getChainHash());

        return new LedgerHeadResponse(
                latest.getSequenceNumber(),
                latest.getChainHash(),
                signatureHex,
                cryptoSigner.getPublicKeyBase64(),
                latest.getCommittedAt()
        );
    }

    /**
     * Traverses and audits the entire cryptographic hash chain link by link.
     */
    @Transactional(readOnly = true)
    public LedgerVerifyResponse verifyLedger() {
        List<LedgerEntryRecord> entries = repository.findAllByOrderBySequenceNumberAsc();

        if (entries.isEmpty()) {
            String genesisSig = cryptoSigner.signHex(HashChainCalculator.GENESIS_HASH);
            boolean sigValid = cryptoSigner.verifyHex(HashChainCalculator.GENESIS_HASH, genesisSig);
            return LedgerVerifyResponse.success(0, HashChainCalculator.GENESIS_HASH, sigValid);
        }

        for (int i = 0; i < entries.size(); i++) {
            LedgerEntryRecord record = entries.get(i);

            // 1. Verify sequence order continuity
            if (record.getSequenceNumber() != (long) i) {
                return LedgerVerifyResponse.corrupted(
                        (long) i,
                        String.format("Sequence discontinuity: expected seq %d but found %d. Subsequent chain unverifiable.",
                                i, record.getSequenceNumber()),
                        entries.size(),
                        record.getChainHash()
                );
            }

            // 2. Verify previousChainHash connection
            if (i == 0) {
                if (!HashChainCalculator.constantTimeEquals(record.getPreviousChainHash(), HashChainCalculator.GENESIS_HASH)) {
                    return LedgerVerifyResponse.corrupted(
                            0L,
                            String.format("Genesis hash corruption at entry 0: expected %s but found %s",
                                    HashChainCalculator.GENESIS_HASH, record.getPreviousChainHash()),
                            entries.size(),
                            record.getChainHash()
                    );
                }
            } else {
                LedgerEntryRecord prev = entries.get(i - 1);
                if (!HashChainCalculator.constantTimeEquals(record.getPreviousChainHash(), prev.getChainHash())) {
                    return LedgerVerifyResponse.corrupted(
                            (long) i,
                            String.format("Hash chain link broken at sequence %d: previousChainHash does not match sequence %d chainHash. All entries from seq %d onwards are unverifiable.",
                                    i, i - 1, i),
                            entries.size(),
                            record.getChainHash()
                    );
                }
            }

            // 3. Verify entryHash integrity against canonicalPayload
            String recomputedEntryHash = HashChainCalculator.calculateEntryHash(record.getCanonicalPayload());
            if (!HashChainCalculator.constantTimeEquals(record.getEntryHash(), recomputedEntryHash)) {
                return LedgerVerifyResponse.corrupted(
                        (long) i,
                        String.format("Payload tampering detected at sequence %d: stored entryHash does not match SHA-256 of canonical payload. All entries from seq %d onwards are unverifiable.",
                                i, i),
                        entries.size(),
                        record.getChainHash()
                );
            }

            // 4. Verify chainHash computation
            String recomputedChainHash = HashChainCalculator.calculateChainHash(
                    record.getPreviousChainHash(), record.getEntryHash());
            if (!HashChainCalculator.constantTimeEquals(record.getChainHash(), recomputedChainHash)) {
                return LedgerVerifyResponse.corrupted(
                        (long) i,
                        String.format("Chain hash mismatch at sequence %d: recomputed chainHash %s differs from stored %s. All entries from seq %d onwards are unverifiable.",
                                i, recomputedChainHash, record.getChainHash(), i),
                        entries.size(),
                        record.getChainHash()
                );
            }
        }

        // 5. Verify Ed25519 signature on head hash
        LedgerEntryRecord head = entries.get(entries.size() - 1);
        String headSig = cryptoSigner.signHex(head.getChainHash());
        boolean sigValid = cryptoSigner.verifyHex(head.getChainHash(), headSig);

        return LedgerVerifyResponse.success(entries.size(), head.getChainHash(), sigValid);
    }

    @Transactional(readOnly = true)
    public Optional<LedgerEntry> getEntry(long sequenceNumber) {
        return repository.findBySequenceNumber(sequenceNumber).map(this::toDto);
    }

    @Transactional(readOnly = true)
    public List<LedgerEntry> getRecentEntries() {
        return repository.findTop50ByOrderBySequenceNumberDesc()
                .stream()
                .map(this::toDto)
                .toList();
    }

    private LedgerEntry toDto(LedgerEntryRecord r) {
        return new LedgerEntry(
                r.getSequenceNumber(),
                new IncidentId(r.getIncidentId()),
                r.getModule(),
                r.getEntryHash(),
                r.getPreviousChainHash(),
                r.getChainHash(),
                r.getCanonicalPayload(),
                r.getCommittedAt()
        );
    }
}
