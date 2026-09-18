import { useQuery } from '@tanstack/react-query';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Chip from '@mui/material/Chip';
import Grid from '@mui/material/Grid';
import Skeleton from '@mui/material/Skeleton';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import ArrowDownwardIcon from '@mui/icons-material/ArrowDownward';
import VerifiedIcon from '@mui/icons-material/VerifiedUserOutlined';

import { api, describeError } from '../api/client';
import { Monospace } from '../components/Monospace';
import type { CertificateDetails } from '../api/types';

interface CertificateOverview {
  signingChain: CertificateDetails[];
  trustAnchors: CertificateDetails[];
  providerName: string;
  description: string;
  developmentPki: boolean;
}

/** Pulls the common name out of a distinguished name for display. */
function commonNameOf(distinguishedName: string): string {
  const match = /CN=([^,]+)/.exec(distinguishedName);
  return match?.[1]?.trim() ?? distinguishedName;
}

function roleOf(index: number, total: number): string {
  if (total === 1) return 'Self-signed signer';
  if (index === 0) return 'Signer (end entity)';
  if (index === total - 1) return 'Root certificate authority';
  return 'Intermediate certificate authority';
}

function CertificateCard({
  certificate,
  role,
  trusted,
}: {
  certificate: CertificateDetails;
  role: string;
  trusted?: boolean;
}) {
  const expired = new Date(certificate.validUntil).getTime() < Date.now();

  return (
    <Card sx={{ width: '100%' }}>
      <CardContent>
        <Stack
          direction="row"
          justifyContent="space-between"
          alignItems="flex-start"
          flexWrap="wrap"
          useFlexGap
          sx={{ mb: 2 }}
        >
          <Box>
            <Typography variant="h6">{commonNameOf(certificate.subject)}</Typography>
            <Typography variant="caption" color="text.secondary">
              {role}
            </Typography>
          </Box>
          <Stack direction="row" spacing={1}>
            {trusted && <Chip size="small" color="success" label="Trust anchor" icon={<VerifiedIcon />} />}
            <Chip
              size="small"
              color={expired ? 'warning' : 'default'}
              variant="outlined"
              label={expired ? 'Expired' : 'Within validity'}
            />
          </Stack>
        </Stack>

        <Grid container spacing={1.5}>
          <Row label="Subject" value={certificate.subject} mono />
          <Row label="Issuer" value={certificate.issuer} mono />
          <Row label="Serial number" value={certificate.serialNumber} mono />
          <Row label="Valid from" value={new Date(certificate.validFrom).toLocaleString()} />
          <Row label="Valid until" value={new Date(certificate.validUntil).toLocaleString()} />
          <Row
            label="Public key"
            value={
              certificate.keySizeBits
                ? certificate.publicKeyAlgorithm + ' ' + certificate.keySizeBits + ' bits'
                : certificate.publicKeyAlgorithm
            }
          />
          <Row label="Signature algorithm" value={certificate.signatureAlgorithm} />
          <Row label="SHA-256 fingerprint" value={certificate.sha256Fingerprint} mono />
          <Row
            label="Key usage"
            value={certificate.keyUsages.length ? certificate.keyUsages.join(', ') : 'Not restricted'}
          />
          {certificate.extendedKeyUsages.length > 0 && (
            <Row label="Extended key usage" value={certificate.extendedKeyUsages.join(', ')} mono />
          )}
          <Row label="X.509 version" value={'v' + certificate.version} />
        </Grid>
      </CardContent>
    </Card>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <>
      <Grid size={{ xs: 12, sm: 4 }}>
        <Typography variant="body2" color="text.secondary">
          {label}
        </Typography>
      </Grid>
      <Grid size={{ xs: 12, sm: 8 }}>
        {mono ? <Monospace>{value}</Monospace> : <Typography variant="body2">{value}</Typography>}
      </Grid>
    </>
  );
}

export function CertificatesPage() {
  const query = useQuery({
    queryKey: ['certificates'],
    queryFn: async (): Promise<CertificateOverview> => {
      const { data } = await api.get<CertificateOverview>('/certificates');
      return data;
    },
  });

  if (query.isLoading) {
    return <Skeleton variant="rounded" height={360} />;
  }

  if (query.isError || !query.data) {
    return <Alert severity="error">{describeError(query.error)}</Alert>;
  }

  const overview = query.data;
  const anchorFingerprints = new Set(overview.trustAnchors.map((a) => a.sha256Fingerprint));

  return (
    <Stack spacing={3}>
      <Box>
        <Typography variant="h4" sx={{ mb: 0.5 }}>
          Certificate explorer
        </Typography>
        <Typography variant="body2" color="text.secondary">
          The signing chain this instance uses, and the anchors it trusts. Only public
          certificate data is shown — private keys are never exposed by any endpoint.
        </Typography>
      </Box>

      {overview.developmentPki && (
        <Alert severity="warning">
          {overview.description}. These certificates are genuine but ephemeral, and no
          external party has any reason to trust them.
        </Alert>
      )}

      <Card>
        <CardContent>
          <Typography variant="subtitle2" color="text.secondary">
            Key custody
          </Typography>
          <Typography variant="body1">{overview.providerName}</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            {overview.description}
          </Typography>
        </CardContent>
      </Card>

      <Box>
        <Typography variant="h6" sx={{ mb: 2 }}>
          Certificate chain
        </Typography>

        {/*
          Rendered root-last, matching how a chain is actually built: from the
          signer upward to the authority that vouches for it.
        */}
        <Stack spacing={1.5} alignItems="center">
          {overview.signingChain.map((certificate, index) => (
            <Box key={certificate.sha256Fingerprint} sx={{ width: '100%' }}>
              <CertificateCard
                certificate={certificate}
                role={roleOf(index, overview.signingChain.length)}
                trusted={anchorFingerprints.has(certificate.sha256Fingerprint)}
              />
              {index < overview.signingChain.length - 1 && (
                <Stack alignItems="center" sx={{ py: 1 }}>
                  <ArrowDownwardIcon color="disabled" />
                  <Typography variant="caption" color="text.secondary">
                    issued by
                  </Typography>
                </Stack>
              )}
            </Box>
          ))}
        </Stack>
      </Box>

      <Box>
        <Typography variant="h6" sx={{ mb: 1 }}>
          Configured trust anchors
        </Typography>
        {overview.trustAnchors.length === 0 ? (
          <Alert severity="warning">
            No trust anchors are configured. Signatures can still verify cryptographically,
            but none can reach a fully trusted verdict — every valid signature will be
            reported as amber rather than green.
          </Alert>
        ) : (
          <Stack spacing={1.5}>
            {overview.trustAnchors.map((anchor) => (
              <CertificateCard key={anchor.sha256Fingerprint} certificate={anchor} role="Trust anchor" trusted />
            ))}
          </Stack>
        )}
      </Box>
    </Stack>
  );
}
