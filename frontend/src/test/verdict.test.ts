import { describe, expect, it } from 'vitest';

import {
  presentCertificate,
  presentChain,
  presentIntegrity,
  presentRevocation,
  presentSignature,
  presentTimestamp,
  presentVerdict,
} from '../components/verdict';
import type { RevocationStatus, TimestampStatus, VerificationVerdict } from '../api/types';

/**
 * These tests guard the product's central honesty property.
 *
 * The backend can be scrupulous about reporting NOT_CHECKED and NOT_AVAILABLE,
 * and all of that is undone if the interface paints them green. The colour a
 * status is rendered in is a security-relevant decision, so it is tested like
 * one.
 */
describe('status presentation', () => {
  describe('never presents absence of evidence as evidence of safety', () => {
    it('renders NOT_CHECKED revocation as neutral, never valid', () => {
      const presentation = presentRevocation('NOT_CHECKED');

      expect(presentation.tone).toBe('neutral');
      expect(presentation.tone).not.toBe('valid');
      expect(presentation.label).toBe('Not checked');
      expect(presentation.hint).toMatch(/nothing was verified/i);
    });

    it('renders UNKNOWN revocation as neutral, never valid', () => {
      expect(presentRevocation('UNKNOWN').tone).toBe('neutral');
    });

    it('renders an ERROR revocation check as neutral, never valid', () => {
      expect(presentRevocation('ERROR').tone).toBe('neutral');
    });

    it('renders NOT_AVAILABLE timestamp as neutral, never valid', () => {
      const presentation = presentTimestamp('NOT_AVAILABLE');

      expect(presentation.tone).toBe('neutral');
      expect(presentation.label).toBe('Not available');
      expect(presentation.hint).toMatch(/cannot be proven/i);
    });

    it('only GOOD revocation is rendered as valid', () => {
      const statuses: RevocationStatus[] = ['GOOD', 'REVOKED', 'UNKNOWN', 'NOT_CHECKED', 'ERROR'];
      const green = statuses.filter((status) => presentRevocation(status).tone === 'valid');

      expect(green).toEqual(['GOOD']);
    });

    it('only a verified token is rendered as a valid timestamp', () => {
      const statuses: TimestampStatus[] = ['VALID', 'INVALID', 'NOT_AVAILABLE', 'NOT_CHECKED'];
      const green = statuses.filter((status) => presentTimestamp(status).tone === 'valid');

      expect(green).toEqual(['VALID']);
    });
  });

  describe('overall verdict', () => {
    it('distinguishes green, amber and red', () => {
      expect(presentVerdict('VALID').tone).toBe('valid');
      expect(presentVerdict('VALID_UNTRUSTED').tone).toBe('untrusted');
      expect(presentVerdict('TAMPERED').tone).toBe('invalid');
      expect(presentVerdict('INVALID').tone).toBe('invalid');
    });

    it('treats an unsigned document as neutral rather than a failure', () => {
      const presentation = presentVerdict('UNSIGNED');

      expect(presentation.tone).toBe('neutral');
      expect(presentation.hint).toMatch(/not a failure/i);
    });

    it('treats an unreadable file as neutral rather than a pass or a fail', () => {
      expect(presentVerdict('ERROR').tone).toBe('neutral');
    });

    it('marks only a fully trusted result green', () => {
      const verdicts: VerificationVerdict[] = [
        'VALID',
        'VALID_UNTRUSTED',
        'TAMPERED',
        'INVALID',
        'UNSIGNED',
        'ERROR',
      ];
      const green = verdicts.filter((verdict) => presentVerdict(verdict).tone === 'valid');

      expect(green).toEqual(['VALID']);
    });
  });

  describe('keeps document integrity separate from certificate validity', () => {
    it('reports modified content as invalid', () => {
      const presentation = presentIntegrity('MODIFIED');

      expect(presentation.tone).toBe('invalid');
      expect(presentation.hint).toMatch(/proof/i);
    });

    it('still reports a valid certificate as valid', () => {
      // The tampered-document case: content changed, certificate untouched.
      expect(presentCertificate('VALID').tone).toBe('valid');
      expect(presentSignature('INVALID').tone).toBe('invalid');
    });

    it('treats an expired certificate as amber rather than red', () => {
      // Expiry does not retroactively forge a signature made while valid.
      expect(presentCertificate('EXPIRED').tone).toBe('untrusted');
    });

    it('treats a revoked certificate as red', () => {
      expect(presentCertificate('REVOKED').tone).toBe('invalid');
    });
  });

  describe('chain trust', () => {
    it('renders an untrusted chain as amber, not red', () => {
      const presentation = presentChain('UNTRUSTED');

      expect(presentation.tone).toBe('untrusted');
      expect(presentation.label).toBe('Not trusted');
    });

    it('renders a broken chain as red', () => {
      expect(presentChain('INVALID').tone).toBe('invalid');
    });

    it('renders an unchecked chain as neutral', () => {
      expect(presentChain('NOT_CHECKED').tone).toBe('neutral');
    });
  });

  describe('every status carries a text label and an explanation', () => {
    it('never returns an empty label or hint', () => {
      const presentations = [
        presentVerdict('VALID'),
        presentVerdict('TAMPERED'),
        presentIntegrity('INTACT'),
        presentSignature('CORRUPTED'),
        presentCertificate('NOT_YET_VALID'),
        presentChain('INCOMPLETE'),
        presentRevocation('NOT_CHECKED'),
        presentTimestamp('NOT_AVAILABLE'),
      ];

      for (const presentation of presentations) {
        // Colour is never the only signal: a text label must always exist,
        // because a colour-only indicator is invisible to many users.
        expect(presentation.label.length).toBeGreaterThan(0);
        expect(presentation.hint.length).toBeGreaterThan(0);
      }
    });
  });
});
