package com.docutrust.signature.infrastructure;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

public interface SignatureRecordRepository extends JpaRepository<SignatureRecordEntity, String> {

    List<SignatureRecordEntity> findByDocumentIdOrderBySignedAtAsc(String documentId);
}
