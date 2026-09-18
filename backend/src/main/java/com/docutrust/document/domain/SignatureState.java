package com.docutrust.document.domain;

/** Whether a stored document has been signed through DocuTrust. */
public enum SignatureState {

    /** Uploaded, not yet signed. */
    UNSIGNED,

    /** At least one signature has been applied. */
    SIGNED
}
