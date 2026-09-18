package com.docutrust.document.application;

import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.docutrust.document.domain.DocumentNotFoundException;
import com.docutrust.document.domain.SignatureState;
import com.docutrust.document.infrastructure.DocumentEntity;
import com.docutrust.document.infrastructure.DocumentRepository;
import com.docutrust.document.infrastructure.DocumentVersionEntity;
import com.docutrust.document.infrastructure.DocumentVersionRepository;
import com.docutrust.signature.infrastructure.SignatureRecordEntity;
import com.docutrust.signature.infrastructure.SignatureRecordRepository;

/**
 * Database writes for documents, kept deliberately small.
 *
 * <p>A separate bean from {@link DocumentService} for two reasons. First,
 * Spring's transactional proxying does not apply to self-invocation, so
 * transactional methods must live on a different bean to take effect at all.
 * Second, it makes the transactional boundary visible: everything here is a
 * short database-only operation, and the slow work — object storage I/O and
 * cryptography — deliberately happens outside it.
 *
 * <p>Holding a transaction open across a signing operation would pin a database
 * connection for the duration of unrelated cryptographic and network work, so a
 * slow key service would present as database exhaustion (specification
 * section 45).
 */
@Service
public class DocumentPersistenceService {

    private final DocumentRepository documents;
    private final DocumentVersionRepository versions;
    private final SignatureRecordRepository signatures;

    public DocumentPersistenceService(DocumentRepository documents,
                                      DocumentVersionRepository versions,
                                      SignatureRecordRepository signatures) {
        this.documents = documents;
        this.versions = versions;
        this.signatures = signatures;
    }

    @Transactional
    public void saveNewDocument(DocumentEntity document, DocumentVersionEntity originalVersion) {
        documents.save(document);
        versions.save(originalVersion);
    }

    @Transactional
    public void saveSignedVersion(String documentId,
                                  DocumentVersionEntity signedVersion,
                                  SignatureRecordEntity signatureRecord) {
        versions.save(signedVersion);
        signatures.save(signatureRecord);

        DocumentEntity document = documents.findById(documentId)
                .orElseThrow(() -> new DocumentNotFoundException(documentId));
        document.setSignatureState(SignatureState.SIGNED);
        documents.save(document);
    }

    @Transactional(readOnly = true)
    public DocumentEntity requireOwnedDocument(String documentId, String ownerId) {
        return documents.findByIdAndOwnerId(documentId, ownerId)
                .orElseThrow(() -> new DocumentNotFoundException(documentId));
    }

    @Transactional(readOnly = true)
    public List<DocumentEntity> listOwnedBy(String ownerId) {
        return documents.findByOwnerIdOrderByUploadedAtDesc(ownerId);
    }

    @Transactional(readOnly = true)
    public List<DocumentVersionEntity> versionsOf(String documentId) {
        return versions.findByDocumentIdOrderByVersionNumberAsc(documentId);
    }

    @Transactional(readOnly = true)
    public Optional<DocumentVersionEntity> latestVersionOf(String documentId) {
        return versions.findFirstByDocumentIdOrderByVersionNumberDesc(documentId);
    }

    @Transactional(readOnly = true)
    public List<SignatureRecordEntity> signaturesOf(String documentId) {
        return signatures.findByDocumentIdOrderBySignedAtAsc(documentId);
    }

    @Transactional(readOnly = true)
    public long countOwnedBy(String ownerId) {
        return documents.countByOwnerId(ownerId);
    }

    @Transactional(readOnly = true)
    public long countSignedBy(String ownerId) {
        return documents.countByOwnerIdAndSignatureState(ownerId, SignatureState.SIGNED);
    }
}
