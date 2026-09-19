package com.trustshield.bot.repository;

import com.trustshield.bot.entity.BotInteractionRecord;
import com.trustshield.common.dto.ThreatLevel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Spring Data JPA repository for bot interactions and channel audit trails.
 */
@Repository
public interface BotInteractionRecordRepository extends JpaRepository<BotInteractionRecord, Long> {

    List<BotInteractionRecord> findTop25ByOrderByCreatedAtDesc();

    long countByThreatLevel(ThreatLevel threatLevel);

    long countByChannel(String channel);

    List<BotInteractionRecord> findBySenderIdOrderByCreatedAtDesc(String senderId);
}
