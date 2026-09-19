package com.trustshield.fakenews.repository;

import com.trustshield.common.dto.ThreatLevel;
import com.trustshield.fakenews.entity.ClaimCheckRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ClaimCheckRecordRepository extends JpaRepository<ClaimCheckRecord, Long> {

    List<ClaimCheckRecord> findTop25ByOrderByCheckedAtDesc();

    long countByThreatLevel(ThreatLevel threatLevel);

    long countBySimHashMatchedTrue();

    long countByFactCheckMatchedTrue();
}
