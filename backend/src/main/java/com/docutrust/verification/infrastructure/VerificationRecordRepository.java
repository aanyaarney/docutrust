package com.docutrust.verification.infrastructure;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.docutrust.verification.domain.VerificationVerdict;

public interface VerificationRecordRepository extends JpaRepository<VerificationRecordEntity, String> {

    Optional<VerificationRecordEntity> findByVerificationId(String verificationId);

    List<VerificationRecordEntity> findTop10ByOrderByVerifiedAtDesc();

    long countByVerdict(VerificationVerdict verdict);

    long countByTamperingDetectedTrue();
}
