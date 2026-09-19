package com.trustshield.breach.repository;

import java.util.List;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import com.trustshield.breach.entity.BreachCheckRecord;

/**
 * Audit-trail access for breach checks.
 *
 * <p>Note there is no {@code findByPassword} or {@code findByEmail} — the schema
 * holds neither, by design. Lookups are by opaque hash or by time only.
 *
 * <p>Everything here is a derived query rather than {@code @Query} JPQL. That is
 * deliberate: Hibernate validates JPQL eagerly at context startup, so a typo in
 * a hand-written query is not a failing endpoint, it is a service that refuses
 * to boot. Derived methods are checked against the metamodel instead, and
 * referring to a nested enum constant in JPQL is exactly the kind of fragile
 * construct worth avoiding two days before a demo.
 */
public interface BreachCheckRecordRepository extends JpaRepository<BreachCheckRecord, Long> {

    List<BreachCheckRecord> findAllByOrderByCheckedAtDesc(Pageable pageable);

    List<BreachCheckRecord> findBySubjectHashOrderByCheckedAtDesc(String subjectHash);

    long countByExposedTrue();

    long countByDegradedTrue();

    long countByCheckType(BreachCheckRecord.CheckType checkType);
}
