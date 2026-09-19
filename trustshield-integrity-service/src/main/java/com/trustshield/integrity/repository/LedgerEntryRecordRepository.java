package com.trustshield.integrity.repository;

import com.trustshield.integrity.entity.LedgerEntryRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface LedgerEntryRecordRepository extends JpaRepository<LedgerEntryRecord, Long> {

    Optional<LedgerEntryRecord> findTopByOrderBySequenceNumberDesc();

    List<LedgerEntryRecord> findAllByOrderBySequenceNumberAsc();

    Optional<LedgerEntryRecord> findBySequenceNumber(long sequenceNumber);

    List<LedgerEntryRecord> findTop50ByOrderBySequenceNumberDesc();
}
