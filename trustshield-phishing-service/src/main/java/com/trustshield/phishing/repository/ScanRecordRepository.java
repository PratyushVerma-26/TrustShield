package com.trustshield.phishing.repository;

import com.trustshield.phishing.entity.ScanRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ScanRecordRepository extends JpaRepository<ScanRecord, Long> {

    /** Most recent scans, for the dashboard's activity feed. */
    List<ScanRecord> findTop25ByOrderByScannedAtDesc();

    /** Count of scans at or above a risk threshold, for the dashboard counters. */
    long countByRiskScoreGreaterThanEqual(int riskScore);

    /** Repeat sightings of the same URL, matched on hash rather than the URL itself. */
    long countByUrlHash(String urlHash);
}
