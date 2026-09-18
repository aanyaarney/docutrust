package com.docutrust.verification.infrastructure;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface VerificationReportRepository extends JpaRepository<VerificationReportEntity, String> {

    Optional<VerificationReportEntity> findByVerificationId(String verificationId);
}
