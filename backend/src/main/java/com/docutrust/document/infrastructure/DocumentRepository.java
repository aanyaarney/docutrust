package com.docutrust.document.infrastructure;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.docutrust.document.domain.SignatureState;

public interface DocumentRepository extends JpaRepository<DocumentEntity, String> {

    List<DocumentEntity> findByOwnerIdOrderByUploadedAtDesc(String ownerId);

    Optional<DocumentEntity> findByIdAndOwnerId(String id, String ownerId);

    long countByOwnerId(String ownerId);

    long countByOwnerIdAndSignatureState(String ownerId, SignatureState signatureState);
}
