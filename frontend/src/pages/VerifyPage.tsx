import { useState } from 'react';
import Accordion from '@mui/material/Accordion';
import AccordionDetails from '@mui/material/AccordionDetails';
import AccordionSummary from '@mui/material/AccordionSummary';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Divider from '@mui/material/Divider';
import Grid from '@mui/material/Grid';
import LinearProgress from '@mui/material/LinearProgress';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import CancelIcon from '@mui/icons-material/Cancel';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import RestartAltIcon from '@mui/icons-material/RestartAlt';
import DownloadIcon from '@mui/icons-material/DownloadOutlined';

import { FileDropzone } from '../components/FileDropzone';
import { Monospace } from '../components/Monospace';
import { CheckCard } from '../components/CheckCard';
import { describeError, verificationApi } from '../api/client';
import type { SignatureVerificationDetail, VerificationReport } from '../api/types';
import {
  presentCertificate,
  presentChain,
  presentIntegrity,
  presentRevocation,
  presentSignature,
  presentTimestamp,
  presentVerdict,
  type Tone,
} from '../components/verdict';
import { verdictPalette } from '../theme';

function verdictIcon(tone: Tone) {
  const sx = { fontSize: 44 };
  switch (tone) {
    case 'valid':
      return <CheckCircleIcon sx={sx} />;
    case 'untrusted':
      return <WarningAmberIcon sx={sx} />;
    case 'invalid':
      return <CancelIcon sx={sx} />;
    default:
      return <HelpOutlineIcon sx={sx} />;
  }
}

function toneColors(tone: Tone) {
  switch (tone) {
    case 'valid':
      return verdictPalette.valid;
    case 'untrusted':
      return verdictPalette.untrusted;
    case 'invalid':
      return verdictPalette.invalid;
    default:
      return verdictPalette.neutral;
  }
}

/**
 * The single, unmissable answer.
 *
 * Deliberately large. A verdict shown as a small chip invites skimming, and the
 * difference between "authentic" and "tampered" is the one thing a reader must
 * not miss. Icon, colour and words all carry the same message so none of them
 * is load-bearing alone.
 */
function VerdictBanner({ report }: { report: VerificationReport }) {
  const presentation = presentVerdict(report.verdict);
  const colors = toneColors(presentation.tone);

  return (
    <Card
      sx={{
        borderLeft: 6,
        borderLeftColor: colors.main,
        bgcolor: (theme) => (theme.palette.mode === 'dark' ? 'background.paper' : colors.light),
      }}
    >
      <CardContent sx={{ p: 3 }}>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2.5} alignItems="flex-start">
          <Box sx={{ color: colors.main, display: 'flex' }}>{verdictIcon(presentation.tone)}</Box>

          <Box sx={{ flexGrow: 1 }}>
            <Typography variant="h4" sx={{ color: colors.main, mb: 1 }}>
              {report.headline}
            </Typography>
            <Typography variant="body1" sx={{ mb: 2, maxWidth: 780, lineHeight: 1.6 }}>
              {report.explanation}
            </Typography>

            <Stack direction="row" spacing={3} flexWrap="wrap" useFlexGap>
              <Box>
                <Typography variant="caption" color="text.secondary" display="block">
                  Verification ID
                </Typography>
                <Monospace>{report.verificationId}</Monospace>
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary" display="block">
                  Signatures found
                </Typography>
                <Typography variant="body2">{report.signatures.length}</Typography>
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary" display="block">
                  Verified at
                </Typography>
                <Typography variant="body2">
                  {new Date(report.verifiedAt).toLocaleString()}
                </Typography>
              </Box>
            </Stack>
          </Box>
        </Stack>
      </CardContent>
    </Card>
  );
}

/** The six independent checks, plus the technical detail drawer. */
function SignaturePanel({
  signature,
  index,
  total,
}: {
  signature: SignatureVerificationDetail;
  index: number;
  total: number;
}) {
  const certificate = signature.certificate;
  const details = certificate.details;

  return (
    <Card>
      <CardContent>
        <Stack
          direction="row"
          justifyContent="space-between"
          alignItems="center"
          flexWrap="wrap"
          sx={{ mb: 2.5 }}
        >
          <Typography variant="h6">
            {total > 1 ? `Signature ${index + 1} of ${total}` : 'Signature details'}
            {signature.signerName ? ` — ${signature.signerName}` : ''}
          </Typography>
        </Stack>

        {/*
          Six independent checks. Each answers a different question, and a
          document can pass some while failing others - a tampered file has a
          failed integrity check and a perfectly valid certificate.
        */}
        <Grid container spacing={2}>
          <Grid size={{ xs: 12, sm: 6, md: 4 }}>
            <CheckCard title="Document integrity" presentation={presentIntegrity(signature.integrity)} />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 4 }}>
            <CheckCard title="Digital signature" presentation={presentSignature(signature.signature)} />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 4 }}>
            <CheckCard title="Certificate" presentation={presentCertificate(certificate.status)} />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 4 }}>
            <CheckCard title="Certificate chain" presentation={presentChain(certificate.chainStatus)} />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 4 }}>
            <CheckCard
              title="Trusted timestamp"
              presentation={presentTimestamp(signature.timestamp)}
            />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 4 }}>
            <CheckCard
              title="Revocation"
              presentation={presentRevocation(certificate.revocationStatus)}
            />
          </Grid>
        </Grid>

        {/* Tamper analysis, with proof clearly separated from interpretation. */}
        <Alert
          severity={
            signature.tamperAnalysis.tampered
              ? 'error'
              : signature.tamperAnalysis.modificationType === 'NONE'
                ? 'success'
                : 'info'
          }
          sx={{ mt: 3 }}
          icon={false}
        >
          <AlertTitle sx={{ fontWeight: 650 }}>
            Modification analysis — {signature.tamperAnalysis.modificationType.replaceAll('_', ' ').toLowerCase()}
          </AlertTitle>
          <Typography variant="body2" sx={{ mb: 1 }}>
            {signature.tamperAnalysis.explanation}
          </Typography>
          <Typography variant="caption" sx={{ fontWeight: 650 }}>
            {signature.tamperAnalysis.cryptographicallyProven
              ? 'This finding is cryptographically proven.'
              : 'This is a best-effort structural observation, not cryptographic proof.'}
          </Typography>
        </Alert>

        {/* Technical detail, for reviewers who want the underlying facts. */}
        <Accordion disableGutters elevation={0} sx={{ mt: 2, border: 1, borderColor: 'divider' }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography variant="subtitle2">Technical details</Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              <DetailRow label="Signature format" value={signature.signatureFormat} />
              <DetailRow label="Digest algorithm" value={signature.digestAlgorithm} />
              <DetailRow label="Signature algorithm" value={signature.signatureAlgorithm} />
              <DetailRow
                label="Signed byte range"
                value={signature.byteRange.length ? `[${signature.byteRange.join(', ')}]` : 'Unavailable'}
                mono
              />
              <DetailRow
                label="Covers whole document"
                value={signature.coversEntireDocument ? 'Yes' : 'No — content follows this signature'}
              />
              <DetailRow
                label="Claimed signing time"
                value={
                  signature.claimedSigningTime
                    ? `${new Date(signature.claimedSigningTime).toLocaleString()} (asserted by signer, not proven)`
                    : 'Not stated'
                }
              />
              <DetailRow
                label="Timestamp authority"
                value={signature.timestampAuthority ?? 'None — no timestamp token present'}
              />
              <DetailRow
                label="Attested time"
                value={
                  signature.timestampAttestedTime
                    ? `${new Date(signature.timestampAttestedTime).toLocaleString()} (attested by a third party)`
                    : 'None — the time of signing cannot be proven'
                }
              />
              <DetailRow label="Reason" value={signature.reason ?? 'Not stated'} />
              <DetailRow label="Location" value={signature.location ?? 'Not stated'} />

              {details && (
                <>
                  <Grid size={12}>
                    <Divider sx={{ my: 1 }} />
                    <Typography variant="subtitle2" sx={{ mb: 1 }}>
                      Signer certificate
                    </Typography>
                  </Grid>
                  <DetailRow label="Subject" value={details.subject} mono />
                  <DetailRow label="Issuer" value={details.issuer} mono />
                  <DetailRow label="Serial number" value={details.serialNumber} mono />
                  <DetailRow label="Valid from" value={new Date(details.validFrom).toLocaleString()} />
                  <DetailRow label="Valid until" value={new Date(details.validUntil).toLocaleString()} />
                  <DetailRow label="Public key" value={
                    details.keySizeBits
                      ? `${details.publicKeyAlgorithm} ${details.keySizeBits} bits`
                      : details.publicKeyAlgorithm
                  } />
                  <DetailRow label="Certificate signature" value={details.signatureAlgorithm} />
                  <DetailRow label="SHA-256 fingerprint" value={details.sha256Fingerprint} mono />
                  <DetailRow
                    label="Key usage"
                    value={details.keyUsages.length ? details.keyUsages.join(', ') : 'Not restricted'}
                  />
                  <DetailRow label="Self-signed" value={details.selfSigned ? 'Yes' : 'No'} />
                </>
              )}

              {certificate.failureReason && (
                <DetailRow label="Certificate note" value={certificate.failureReason} />
              )}
            </Grid>
          </AccordionDetails>
        </Accordion>
      </CardContent>
    </Card>
  );
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <>
      <Grid size={{ xs: 12, sm: 4 }}>
        <Typography variant="body2" color="text.secondary">
          {label}
        </Typography>
      </Grid>
      <Grid size={{ xs: 12, sm: 8 }}>
        {mono ? (
          <Monospace>{value}</Monospace>
        ) : (
          <Typography variant="body2">{value}</Typography>
        )}
      </Grid>
    </>
  );
}

/** Short explainer, so the page is useful to non-specialists too. */
function EducationCard() {
  return (
    <Card>
      <CardContent>
        <Typography variant="h6" sx={{ mb: 2 }}>
          What a digital signature proves
        </Typography>
        <Stack spacing={2}>
          <Box>
            <Typography variant="subtitle2">Identity</Typography>
            <Typography variant="body2" color="text.secondary">
              Which certificate — and therefore which private key — produced the signature.
            </Typography>
          </Box>
          <Box>
            <Typography variant="subtitle2">Integrity</Typography>
            <Typography variant="body2" color="text.secondary">
              Whether the signed content changed by even a single byte. The digest is
              recomputed over the exact range the signature covers.
            </Typography>
          </Box>
          <Box>
            <Typography variant="subtitle2">Trust</Typography>
            <Typography variant="body2" color="text.secondary">
              Whether the signer's certificate chains to an authority this system was
              configured to trust. A valid signature from an unknown signer is amber,
              not green.
            </Typography>
          </Box>
          <Divider />
          <Box>
            <Typography variant="subtitle2">What it does not prove</Typography>
            <Typography variant="body2" color="text.secondary">
              Without a trusted timestamp, it does not prove <em>when</em> the document was
              signed. It also says nothing about whether the content is true — only that
              it is unchanged since signing.
            </Typography>
          </Box>
        </Stack>
      </CardContent>
    </Card>
  );
}

export function VerifyPage() {
  const [report, setReport] = useState<VerificationReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);

  const handleFile = async (file: File) => {
    setBusy(true);
    setError(null);
    setReport(null);
    setFileName(file.name);
    try {
      setReport(await verificationApi.verify(file));
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  };

  const reset = () => {
    setReport(null);
    setError(null);
    setFileName(null);
  };

  const downloadReport = async (verificationId: string, format: 'html' | 'json') => {
    try {
      await verificationApi.downloadReport(verificationId, format);
    } catch (e) {
      setError(describeError(e));
    }
  };

  return (
    <Stack spacing={3}>
      <Box>
        <Typography variant="h4" sx={{ mb: 0.5 }}>
          Verify a document
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Submit any signed PDF. Verification depends only on the file's own contents and
          the configured trust anchors — no record in this system is consulted to decide
          whether a signature is valid.
        </Typography>
      </Box>

      {!report && (
        <Card>
          <CardContent>
            <FileDropzone
              onFileSelected={handleFile}
              disabled={busy}
              label="Drop a signed PDF here"
              hint="or click to choose a file"
            />
            {busy && (
              <Box sx={{ mt: 2 }}>
                <LinearProgress />
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  Verifying {fileName}…
                </Typography>
              </Box>
            )}
          </CardContent>
        </Card>
      )}

      {error && <Alert severity="error">{error}</Alert>}

      {report && (
        <>
          <VerdictBanner report={report} />

          <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap" useFlexGap>
            <Button startIcon={<RestartAltIcon />} onClick={reset} variant="outlined">
              Verify another document
            </Button>
            <Button
              startIcon={<DownloadIcon />}
              variant="contained"
              onClick={() => downloadReport(report.verificationId, 'html')}
            >
              Download report
            </Button>
            <Button
              startIcon={<DownloadIcon />}
              variant="outlined"
              onClick={() => downloadReport(report.verificationId, 'json')}
            >
              JSON
            </Button>
            <Typography variant="body2" color="text.secondary">
              {report.fileName} · {report.fileSizeBytes.toLocaleString()} bytes
              {report.pageCount ? ` · ${report.pageCount} page${report.pageCount === 1 ? '' : 's'}` : ''}
            </Typography>
          </Stack>

          <Card>
            <CardContent>
              <Typography variant="caption" color="text.secondary" display="block">
                SHA-256 of the submitted file
              </Typography>
              <Monospace>{report.documentSha256}</Monospace>
            </CardContent>
          </Card>

          {report.signatures.map((signature, index) => (
            <SignaturePanel
              key={signature.index}
              signature={signature}
              index={index}
              total={report.signatures.length}
            />
          ))}

          <EducationCard />
        </>
      )}

      {!report && !busy && <EducationCard />}
    </Stack>
  );
}
