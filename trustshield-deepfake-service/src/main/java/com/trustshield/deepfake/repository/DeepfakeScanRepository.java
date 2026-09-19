package com.trustshield.deepfake.repository;

import com.trustshield.common.dto.ThreatLevel;
import com.trustshield.deepfake.entity.DeepfakeScanRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DeepfakeScanRepository extends JpaRepository<DeepfakeScanRecord, Long> {

    List<DeepfakeScanRecord> findTop25ByOrderByScannedAtDesc();

    long countByRiskScoreGreaterThanEqual(int score);

    long countByThreatLevel(ThreatLevel threatLevel);
}
