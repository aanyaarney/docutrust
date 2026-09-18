/**
 * TypeScript mirrors of the backend API contract.
 *
 * The status unions are written out literally rather than as `string`. That is
 * deliberate: the distinction between GOOD and NOT_CHECKED, or between VALID
 * and VALID_UNTRUSTED, is the whole point of the product. Typing them as plain
 * strings would let a rendering bug quietly collapse "we did not check" into
 * "all clear", which is exactly the failure this system exists to prevent.
 */

/** Overall answer about a document. Three of these map to green / amber / red. */
export type VerificationVerdict =
  | 'VALID'
  | 'VALID_UNTRUSTED'
  | 'TAMPERED'
  | 'INVALID'
  | 'UNSIGNED'
  | 'ERROR';

export type IntegrityStatus = 'INTACT' | 'MODIFIED' | 'UNKNOWN';

export type SignatureStatus = 'VALID' | 'INVALID' | 'CORRUPTED' | 'UNKNOWN';

export type CertificateStatus =
  | 'VALID'
  | 'EXPIRED'
  | 'NOT_YET_VALID'
  | 'REVOKED'
  | 'INVALID'
  | 'UNKNOWN';

export type ChainStatus = 'TRUSTED' | 'UNTRUSTED' | 'INCOMPLETE' | 'INVALID' | 'NOT_CHECKED';

/** NOT_CHECKED must never be rendered as though it were GOOD. */
export type RevocationStatus = 'GOOD' | 'REVOKED' | 'UNKNOWN' | 'NOT_CHECKED' | 'ERROR';

/** NOT_AVAILABLE must never be rendered as though it were VALID. */
export type TimestampStatus = 'VALID' | 'INVALID' | 'NOT_AVAILABLE' | 'NOT_CHECKED';

export type ModificationType =
  | 'NONE'
  | 'SIGNED_CONTENT_CHANGED'
  | 'POST_SIGNATURE_INCREMENTAL_UPDATE'
  | 'SIGNATURE_CORRUPTED'
  | 'UNSUPPORTED_CHANGE'
  | 'UNKNOWN';

export interface CertificateDetails {
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validUntil: string;
  publicKeyAlgorithm: string;
  keySizeBits: number | null;
  signatureAlgorithm: string;
  sha256Fingerprint: string;
  keyUsages: string[];
  extendedKeyUsages: string[];
  selfSigned: boolean;
  version: number;
}

export interface CertificateValidationResult {
  status: CertificateStatus;
  details: CertificateDetails | null;
  validPeriod: boolean;
  chainStatus: ChainStatus;
  revocationStatus: RevocationStatus;
  chain: CertificateDetails[];
  failureReason: string | null;
}

export interface TamperAnalysisResult {
  tampered: boolean;
  modificationType: ModificationType;
  explanation: string;
  affectedRevision: number | null;
  /**
   * True only when the finding rests on a digest mismatch — mathematical
   * proof. False for structural observations, which are interpretation.
   */
  cryptographicallyProven: boolean;
}

export interface SignatureVerificationDetail {
  index: number;
  signerName: string | null;
  reason: string | null;
  location: string | null;
  claimedSigningTime: string | null;
  integrity: IntegrityStatus;
  signature: SignatureStatus;
  certificate: CertificateValidationResult;
  timestamp: TimestampStatus;
  /** TSA named in the token, or null when no token is present. */
  timestampAuthority: string | null;
  /**
   * Time an independent authority attested. Deliberately separate from
   * `claimedSigningTime`, which the signer asserts and nobody verified.
   */
  timestampAttestedTime: string | null;
  tamperAnalysis: TamperAnalysisResult;
  signatureFormat: string;
  digestAlgorithm: string;
  signatureAlgorithm: string;
  byteRange: number[];
  coversEntireDocument: boolean;
  verdict: VerificationVerdict;
}

export interface VerificationReport {
  verificationId: string;
  verdict: VerificationVerdict;
  headline: string;
  explanation: string;
  signatures: SignatureVerificationDetail[];
  documentSha256: string;
  fileName: string | null;
  pageCount: number | null;
  fileSizeBytes: number;
  verifiedAt: string;
}

export interface DocumentSummary {
  id: string;
  fileName: string;
  sizeBytes: number;
  sha256: string;
  pageCount: number | null;
  signatureState: 'UNSIGNED' | 'SIGNED';
  uploadedAt: string;
}

export interface SignResponse {
  documentId: string;
  signerCommonName: string;
  certificateSubject: string;
  certificateIssuer: string;
  certificateSerialNumber: string;
  signatureAlgorithm: string;
  digestAlgorithm: string;
  signatureFormat: string;
  providerName: string;
  signingTime: string;
  signedSizeBytes: number;
}

export interface DocumentVersion {
  versionNumber: number;
  sha256: string;
  sizeBytes: number;
  signed: boolean;
  createdAt: string;
}

export interface SignatureRecord {
  signerCommonName: string | null;
  certificateSubject: string | null;
  certificateIssuer: string | null;
  certificateSerial: string | null;
  signatureAlgorithm: string;
  digestAlgorithm: string;
  signatureFormat: string;
  reason: string | null;
  location: string | null;
  signedAt: string;
}

export interface AuditRecord {
  sequence: number;
  id: string;
  eventType: string;
  documentId: string | null;
  userId: string | null;
  timestamp: string;
  ipAddress: string | null;
  correlationId: string | null;
  details: string | null;
  previousRecordHash: string;
  recordHash: string;
}

export interface DashboardSummary {
  documentsUploaded: number;
  documentsSigned: number;
  validVerifications: number;
  untrustedVerifications: number;
  failedVerifications: number;
  tamperingDetected: number;
  trustAnchors: number;
  auditChainIntact: boolean;
  auditChainExplanation: string;
  signingMaterialDescription: string;
  /** True when signing uses an ephemeral development PKI. Always surfaced. */
  developmentPki: boolean;
  recentActivity: AuditRecord[];
}

export interface LoginResponse {
  token: string;
  tokenType: string;
  expiresInSeconds: number;
  userId: string;
  email: string;
  displayName: string;
  role: 'USER' | 'VERIFIER' | 'ADMIN';
}

export interface ApiErrorBody {
  code: string;
  message: string;
  correlationId: string;
  timestamp: string;
}
