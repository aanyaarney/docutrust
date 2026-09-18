package com.docutrust.verification.application;

import com.docutrust.verification.domain.TamperAnalysisResult;

/**
 * Classifies what happened to a document, from evidence gathered during
 * signature verification.
 *
 * <p>The ordering of the checks encodes a priority: report the strongest,
 * most certain finding first. A corrupted signature is a different fault from
 * modified content, and modified content is a different fault from an appended
 * revision. Merging them would lose information a reader needs.
 *
 * <p>Deliberately conservative. This service reports <em>that</em> content
 * changed and on what evidence, never <em>which</em> content changed.
 * Identifying changed text would require the original document, which a
 * verifier does not have — asserting it anyway would be a fabricated finding
 * (specification sections 18 and 66).
 */
public class TamperAnalysisService {

    /**
     * Produces a modification classification from observed evidence.
     */
    public TamperAnalysisResult classify(SignatureEvidence evidence) {
        // 1. The signature structure is unusable. Nothing further can be said
        //    about integrity, because there is no trustworthy digest to compare.
        if (!evidence.cmsParsed()) {
            return TamperAnalysisResult.signatureCorrupted();
        }

        // 2. Cryptographic proof of modification: the bytes covered by the
        //    signature no longer digest to the value recorded when signed.
        if (evidence.digestMismatch()) {
            return TamperAnalysisResult.signedContentChanged(
                    evidence.signatureIndex() + 1);
        }

        // 3. Digest matched but the signature did not verify. The content is
        //    intact; the signature is the problem - corrupted signature bytes,
        //    or a signature produced by a key other than the one certified.
        if (!evidence.signatureVerified()) {
            return new TamperAnalysisResult(
                    false,
                    com.docutrust.verification.domain.ModificationType.SIGNATURE_CORRUPTED,
                    "The content covered by this signature is unchanged, but the signature does "
                            + "not verify against the signer certificate's public key. The signature "
                            + "value may be damaged, or it may have been produced by a different key "
                            + "than the certificate presents.",
                    null,
                    true);
        }

        // 4. Signature verifies and content is intact, but material was appended
        //    afterwards. Normal PDF behaviour; surfaced, not condemned.
        if (!evidence.coversEntireDocument()) {
            return TamperAnalysisResult.postSignatureUpdate(
                    evidence.revisionCount(), evidence.signatureIndex() + 2);
        }

        // 5. Everything checks out.
        return TamperAnalysisResult.none();
    }
}
