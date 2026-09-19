package com.trustshield.fusion.repository;

import com.trustshield.common.dto.ThreatLevel;
import com.trustshield.fusion.entity.IncidentFusionRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Spring Data JPA repository for cross-modal incident fusion audit history.
 */
@Repository
public interface IncidentFusionRecordRepository extends JpaRepository<IncidentFusionRecord, Long> {

    List<IncidentFusionRecord> findTop25ByOrderByEvaluatedAtDesc();

    long countByThreatLevel(ThreatLevel threatLevel);

    long countByLedgerVerifiedFalse();

    long countBySafeDisallowedTrue();
}
