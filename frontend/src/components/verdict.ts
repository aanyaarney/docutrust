import type {
  CertificateStatus,
  ChainStatus,
  IntegrityStatus,
  RevocationStatus,
  SignatureStatus,
  TimestampStatus,
  VerificationVerdict,
} from '../api/types';

/**
 * Presentation rules for every status the API reports.
 *
 * Centralised deliberately. If each screen decided its own colours and labels,
 * one of them would eventually render NOT_CHECKED in green or call
 * NOT_AVAILABLE "valid", and the whole product's credibility rests on that
 * never happening.
 */

export type Tone = 'valid' | 'untrusted' | 'invalid' | 'neutral';

export interface StatusPresentation {
  label: string;
  tone: Tone;
  /** Short explanation shown in a tooltip. */
  hint: string;
}

/** Maps a tone to a Material UI colour. */
export function toneToColor(tone: Tone): 'success' | 'warning' | 'error' | 'default' {
  switch (tone) {
    case 'valid':
      return 'success';
    case 'untrusted':
      return 'warning';
    case 'invalid':
      return 'error';
    default:
      return 'default';
  }
}

export function presentVerdict(verdict: VerificationVerdict): StatusPresentation {
  switch (verdict) {
    case 'VALID':
      return {
        label: 'Authentic document',
        tone: 'valid',
        hint: 'The signature verifies, the content is unchanged, and the signer chains to a trusted authority.',
      };
    case 'VALID_UNTRUSTED':
      return {
        label: 'Valid signature — trust not established',
        tone: 'untrusted',
        hint: 'The cryptography is sound and the content is unchanged, but the signer cannot be traced to a trusted authority.',
      };
    case 'TAMPERED':
      return {
        label: 'Tampering detected',
        tone: 'invalid',
        hint: 'Content protected by the signature changed after it was signed.',
      };
    case 'INVALID':
      return {
        label: 'Invalid signature',
        tone: 'invalid',
        hint: 'The signature does not verify against the signer certificate.',
      };
    case 'UNSIGNED':
      return {
        label: 'No digital signature',
        tone: 'neutral',
        hint: 'This document carries no signature, so nothing can be verified. This is a fact, not a failure.',
      };
    case 'ERROR':
      return {
        label: 'Could not be read',
        tone: 'neutral',
        hint: 'The file could not be parsed as a PDF, so no conclusion can be drawn.',
      };
  }
}

export function presentIntegrity(status: IntegrityStatus): StatusPresentation {
  switch (status) {
    case 'INTACT':
      return {
        label: 'Intact',
        tone: 'valid',
        hint: 'The digest recomputed over the signed byte range matches the digest inside the signature exactly.',
      };
    case 'MODIFIED':
      return {
        label: 'Modified',
        tone: 'invalid',
        hint: 'The recomputed digest does not match. This is cryptographic proof that the signed content changed.',
      };
    case 'UNKNOWN':
      return { label: 'Unknown', tone: 'neutral', hint: 'Integrity could not be evaluated.' };
  }
}

export function presentSignature(status: SignatureStatus): StatusPresentation {
  switch (status) {
    case 'VALID':
      return {
        label: 'Valid',
        tone: 'valid',
        hint: "The signature verifies against the signer certificate's public key.",
      };
    case 'INVALID':
      return {
        label: 'Invalid',
        tone: 'invalid',
        hint: 'The signature does not verify — the content changed, or a different key produced it.',
      };
    case 'CORRUPTED':
      return {
        label: 'Corrupted',
        tone: 'invalid',
        hint: 'The signature structure could not be parsed. Its bytes are damaged.',
      };
    case 'UNKNOWN':
      return { label: 'Unknown', tone: 'neutral', hint: 'The signature was not evaluated.' };
  }
}

export function presentCertificate(status: CertificateStatus): StatusPresentation {
  switch (status) {
    case 'VALID':
      return {
        label: 'Valid',
        tone: 'valid',
        hint: 'The certificate parsed correctly and is within its validity period.',
      };
    case 'EXPIRED':
      return {
        label: 'Expired',
        tone: 'untrusted',
        hint: 'The certificate is past its expiry date. Signatures made while it was valid are not retroactively forged.',
      };
    case 'NOT_YET_VALID':
      return {
        label: 'Not yet valid',
        tone: 'untrusted',
        hint: 'The certificate’s validity period has not started.',
      };
    case 'REVOKED':
      return {
        label: 'Revoked',
        tone: 'invalid',
        hint: 'The issuing authority reported this certificate as revoked.',
      };
    case 'INVALID':
      return {
        label: 'Invalid',
        tone: 'invalid',
        hint: 'The certificate is unusable — unparseable, or its key usage forbids signing.',
      };
    case 'UNKNOWN':
      return { label: 'Unknown', tone: 'neutral', hint: 'No certificate was available.' };
  }
}

export function presentChain(status: ChainStatus): StatusPresentation {
  switch (status) {
    case 'TRUSTED':
      return {
        label: 'Trusted',
        tone: 'valid',
        hint: 'The chain was built all the way to a configured trust anchor.',
      };
    case 'UNTRUSTED':
      return {
        label: 'Not trusted',
        tone: 'untrusted',
        hint: 'The chain is internally coherent but does not reach any configured trust anchor.',
      };
    case 'INCOMPLETE':
      return {
        label: 'Incomplete',
        tone: 'untrusted',
        hint: 'Issuer certificates needed to complete the chain were not available.',
      };
    case 'INVALID':
      return {
        label: 'Broken',
        tone: 'invalid',
        hint: 'A certificate in the chain is not correctly signed by its stated issuer.',
      };
    case 'NOT_CHECKED':
      return { label: 'Not checked', tone: 'neutral', hint: 'Chain evaluation was not performed.' };
  }
}

/**
 * Revocation.
 *
 * NOT_CHECKED is neutral, never green. Reporting "no check was made" as though
 * it were a clean result is precisely the false assurance this product exists
 * to avoid.
 */
export function presentRevocation(status: RevocationStatus): StatusPresentation {
  switch (status) {
    case 'GOOD':
      return {
        label: 'Good',
        tone: 'valid',
        hint: 'A revocation responder was queried and confirmed this certificate is not revoked.',
      };
    case 'REVOKED':
      return {
        label: 'Revoked',
        tone: 'invalid',
        hint: 'A revocation responder reported this certificate as revoked.',
      };
    case 'UNKNOWN':
      return {
        label: 'Unknown',
        tone: 'neutral',
        hint: 'A check was attempted but the responder could not answer authoritatively.',
      };
    case 'NOT_CHECKED':
      return {
        label: 'Not checked',
        tone: 'neutral',
        hint: 'No revocation check was performed. This is not a pass — nothing was verified.',
      };
    case 'ERROR':
      return {
        label: 'Check failed',
        tone: 'neutral',
        hint: 'A check was attempted but failed technically.',
      };
  }
}

/** Timestamps. NOT_AVAILABLE is neutral, never green. */
export function presentTimestamp(status: TimestampStatus): StatusPresentation {
  switch (status) {
    case 'VALID':
      return {
        label: 'Valid',
        tone: 'valid',
        hint: 'An RFC 3161 timestamp token is present and verifies against a trusted authority.',
      };
    case 'INVALID':
      return { label: 'Invalid', tone: 'invalid', hint: 'A timestamp token is present but does not verify.' };
    case 'NOT_AVAILABLE':
      return {
        label: 'Not available',
        tone: 'neutral',
        hint: 'No trusted timestamp is present, so the time of signing cannot be proven. The signer’s claimed time is an assertion, not evidence.',
      };
    case 'NOT_CHECKED':
      return { label: 'Not checked', tone: 'neutral', hint: 'A token is present but was not evaluated.' };
  }
}
