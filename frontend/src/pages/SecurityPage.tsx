import { useQuery } from '@tanstack/react-query';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Chip from '@mui/material/Chip';
import Grid from '@mui/material/Grid';
import Skeleton from '@mui/material/Skeleton';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import GppBadIcon from '@mui/icons-material/GppBadOutlined';
import GppGoodIcon from '@mui/icons-material/GppGoodOutlined';
import GppMaybeIcon from '@mui/icons-material/GppMaybeOutlined';
import ShieldIcon from '@mui/icons-material/ShieldOutlined';

import { dashboardApi, describeError } from '../api/client';
import { EmptyState } from '../components/EmptyState';
import { verdictPalette } from '../theme';
import type { AuditRecord } from '../api/types';

type Severity = 'HIGH' | 'MEDIUM' | 'LOW';

interface SecurityAlert {
  severity: Severity;
  title: string;
  detail: string;
  at: string;
}

/**
 * Derives security alerts from audit events.
 *
 * Severity reflects what the event actually proves, not how alarming it sounds.
 * Proven tampering is HIGH because a digest mismatch is mathematical evidence
 * that a document is not what was signed. A failed login is LOW on its own —
 * people mistype passwords — and only becomes interesting in volume, which the
 * rate limiter handles rather than this list.
 */
function alertsFrom(events: AuditRecord[]): SecurityAlert[] {
  const alerts: SecurityAlert[] = [];

  for (const event of events) {
    switch (event.eventType) {
      case 'TAMPERING_DETECTED':
        alerts.push({
          severity: 'HIGH',
          title: 'Signed document modified after signing',
          detail: event.details ?? 'A verification found cryptographically proven modification.',
          at: event.timestamp,
        });
        break;
      case 'VERIFICATION_FAILED':
        alerts.push({
          severity: 'MEDIUM',
          title: 'Verification returned a failing verdict',
          detail: event.details ?? 'A submitted document did not verify.',
          at: event.timestamp,
        });
        break;
      case 'SIGNING_FAILED':
        alerts.push({
          severity: 'MEDIUM',
          title: 'Signing operation failed',
          detail: event.details ?? 'A signature could not be produced.',
          at: event.timestamp,
        });
        break;
      case 'AUTHENTICATION_FAILED':
        alerts.push({
          severity: 'LOW',
          title: 'Failed sign-in attempt',
          detail: 'Credentials were rejected. Repeated attempts are throttled automatically.',
          at: event.timestamp,
        });
        break;
      case 'AUTHORIZATION_DENIED':
        alerts.push({
          severity: 'MEDIUM',
          title: 'Permission denied',
          detail: event.details ?? 'A user attempted an action their role does not permit.',
          at: event.timestamp,
        });
        break;
      default:
        break;
    }
  }

  const rank: Record<Severity, number> = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  return alerts.sort((a, b) => rank[a.severity] - rank[b.severity]);
}

function severityColor(severity: Severity): 'error' | 'warning' | 'info' {
  return severity === 'HIGH' ? 'error' : severity === 'MEDIUM' ? 'warning' : 'info';
}

function Metric({
  label,
  value,
  color,
  icon,
  note,
}: {
  label: string;
  value: number;
  color?: string;
  icon: React.ReactNode;
  note?: string;
}) {
  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
          <Box sx={{ color: color ?? 'text.secondary', display: 'flex' }}>{icon}</Box>
          <Typography variant="subtitle2" color="text.secondary">
            {label}
          </Typography>
        </Stack>
        <Typography variant="h4" sx={{ color: color ?? 'text.primary' }}>
          {value}
        </Typography>
        {note && (
          <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 0.5 }}>
            {note}
          </Typography>
        )}
      </CardContent>
    </Card>
  );
}

export function SecurityPage() {
  const summaryQuery = useQuery({
    queryKey: ['dashboard'],
    queryFn: dashboardApi.summary,
    refetchInterval: 15_000,
  });

  if (summaryQuery.isLoading) {
    return <Skeleton variant="rounded" height={420} />;
  }

  if (summaryQuery.isError || !summaryQuery.data) {
    return <Alert severity="error">{describeError(summaryQuery.error)}</Alert>;
  }

  const summary = summaryQuery.data;
  const alerts = alertsFrom(summary.recentActivity);

  return (
    <Stack spacing={3}>
      <Box>
        <Typography variant="h4" sx={{ mb: 0.5 }}>
          Security dashboard
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Verification outcomes, integrity status and recent security events.
        </Typography>
      </Box>

      {summary.developmentPki && (
        <Alert severity="warning">
          <AlertTitle>Development signing key in use</AlertTitle>
          {summary.signingMaterialDescription}. Signatures produced by this instance are
          cryptographically genuine but carry no external trust.
        </Alert>
      )}

      <Grid container spacing={2}>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Metric
            label="Successful verifications"
            value={summary.validVerifications}
            icon={<GppGoodIcon />}
            color={verdictPalette.valid.main}
            note="Signature valid, content intact, chain trusted"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Metric
            label="Untrusted certificates"
            value={summary.untrustedVerifications}
            icon={<GppMaybeIcon />}
            color={verdictPalette.untrusted.main}
            note="Valid cryptography, unproven signer"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Metric
            label="Invalid signatures"
            value={summary.failedVerifications}
            icon={<GppBadIcon />}
            color={summary.failedVerifications > 0 ? verdictPalette.invalid.main : undefined}
            note="Signature failed cryptographic verification"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Metric
            label="Tampering detected"
            value={summary.tamperingDetected}
            icon={<ShieldIcon />}
            color={summary.tamperingDetected > 0 ? verdictPalette.invalid.main : undefined}
            note="Proven modification of signed content"
          />
        </Grid>
      </Grid>

      <Grid container spacing={2}>
        <Grid size={{ xs: 12, md: 6 }}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 1.5 }}>
                Audit chain integrity
              </Typography>
              <Alert severity={summary.auditChainIntact ? 'success' : 'error'} sx={{ mb: 1.5 }}>
                {summary.auditChainIntact ? 'Chain verified' : 'Chain broken'}
              </Alert>
              <Typography variant="body2" color="text.secondary">
                {summary.auditChainExplanation}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12, md: 6 }}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 1.5 }}>
                Trust and key custody
              </Typography>
              <Stack spacing={1.5}>
                <Box>
                  <Typography variant="caption" color="text.secondary" display="block">
                    Configured trust anchors
                  </Typography>
                  <Typography variant="body2">{summary.trustAnchors}</Typography>
                </Box>
                <Box>
                  <Typography variant="caption" color="text.secondary" display="block">
                    Signing key custody
                  </Typography>
                  <Typography variant="body2">{summary.signingMaterialDescription}</Typography>
                </Box>
                <Box>
                  <Typography variant="caption" color="text.secondary" display="block">
                    Revocation and timestamping
                  </Typography>
                  <Typography variant="body2">
                    Not configured. Revocation is reported as “not checked” and timestamps as
                    “not available” — never as passing checks.
                  </Typography>
                </Box>
              </Stack>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Card>
        <CardContent>
          <Typography variant="h6" sx={{ mb: 2 }}>
            Recent security alerts
          </Typography>

          {alerts.length === 0 ? (
            <EmptyState
              icon={<ShieldIcon />}
              title="No security events"
              description="Nothing of security interest has been recorded. Verify a tampered document to see how detection is reported."
            />
          ) : (
            <Stack spacing={1.5}>
              {alerts.map((alert, index) => (
                <Alert
                  key={`${alert.at}-${index}`}
                  severity={severityColor(alert.severity)}
                  icon={false}
                >
                  <Stack
                    direction="row"
                    spacing={1.5}
                    alignItems="center"
                    flexWrap="wrap"
                    useFlexGap
                    sx={{ mb: 0.5 }}
                  >
                    <Chip
                      size="small"
                      label={alert.severity}
                      color={severityColor(alert.severity)}
                    />
                    <Typography variant="subtitle2">{alert.title}</Typography>
                    <Typography variant="caption" color="text.secondary">
                      {new Date(alert.at).toLocaleString()}
                    </Typography>
                  </Stack>
                  <Typography variant="body2">{alert.detail}</Typography>
                </Alert>
              ))}
            </Stack>
          )}
        </CardContent>
      </Card>
    </Stack>
  );
}
