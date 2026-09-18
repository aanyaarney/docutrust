package com.docutrust.document.infrastructure;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface DocumentVersionRepository extends JpaRepository<DocumentVersionEntity, String> {

    List<DocumentVersionEntity> findByDocumentIdOrderByVersionNumberAsc(String documentId);

    Optional<DocumentVersionEntity> findFirstByDocumentIdOrderByVersionNumberDesc(String documentId);

    Optional<DocumentVersionEntity> findByDocumentIdAndVersionNumber(String documentId, int versionNumber);
}
