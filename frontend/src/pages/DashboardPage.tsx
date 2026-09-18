import { useQuery } from '@tanstack/react-query';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Grid from '@mui/material/Grid';
import Skeleton from '@mui/material/Skeleton';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/material/styles';
import DescriptionIcon from '@mui/icons-material/DescriptionOutlined';
import DrawIcon from '@mui/icons-material/DrawOutlined';
import GppGoodIcon from '@mui/icons-material/GppGoodOutlined';
import GppBadIcon from '@mui/icons-material/GppBadOutlined';
import LinkIcon from '@mui/icons-material/LinkOutlined';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip as ChartTooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { dashboardApi, describeError } from '../api/client';
import { verdictPalette } from '../theme';
import type { ReactNode } from 'react';

function StatCard({
  label,
  value,
  icon,
  color,
}: {
  label: string;
  value: number | string;
  icon: ReactNode;
  color?: string;
}) {
  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
          <Box sx={{ color: color ?? 'text.secondary', display: 'flex' }}>{icon}</Box>
          <Typography variant="subtitle2" color="text.secondary">
            {label}
          </Typography>
        </Stack>
        <Typography variant="h4" sx={{ color: color ?? 'text.primary' }}>
          {value}
        </Typography>
      </CardContent>
    </Card>
  );
}

export function DashboardPage() {
  const theme = useTheme();
  const summaryQuery = useQuery({
    queryKey: ['dashboard'],
    queryFn: dashboardApi.summary,
    refetchInterval: 15_000,
  });

  if (summaryQuery.isLoading) {
    return (
      <Grid container spacing={2}>
        {[0, 1, 2, 3].map((i) => (
          <Grid size={{ xs: 12, sm: 6, md: 3 }} key={i}>
            <Skeleton variant="rounded" height={124} />
          </Grid>
        ))}
      </Grid>
    );
  }

  if (summaryQuery.isError || !summaryQuery.data) {
    return <Alert severity="error">{describeError(summaryQuery.error)}</Alert>;
  }

  const summary = summaryQuery.data;

  const verificationData = [
    { name: 'Valid', value: summary.validVerifications, fill: verdictPalette.valid.main },
    { name: 'Untrusted', value: summary.untrustedVerifications, fill: verdictPalette.untrusted.main },
    { name: 'Invalid', value: summary.failedVerifications, fill: verdictPalette.invalid.main },
    { name: 'Tampered', value: summary.tamperingDetected, fill: verdictPalette.invalid.dark },
  ];

  const totalVerifications = verificationData.reduce((sum, entry) => sum + entry.value, 0);
  const successRatio =
    totalVerifications === 0
      ? null
      : Math.round((summary.validVerifications / totalVerifications) * 100);

  return (
    <Stack spacing={3}>
      <Box>
        <Typography variant="h4" sx={{ mb: 0.5 }}>
          Dashboard
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Activity and system integrity at a glance.
        </Typography>
      </Box>

      {/*
        The development-PKI warning is deliberately prominent and always
        rendered when active. A demonstration must never be mistakable for a
        trustworthy deployment.
      */}
      {summary.developmentPki && (
        <Alert severity="warning">
          <AlertTitle>Development signing key in use</AlertTitle>
          {summary.signingMaterialDescription}. The keys are real, but they are regenerated
          on every restart and carry no external trust. Do not use this instance to sign
          anything of legal or commercial value.
        </Alert>
      )}

      <Grid container spacing={2}>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <StatCard
            label="Documents uploaded"
            value={summary.documentsUploaded}
            icon={<DescriptionIcon />}
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <StatCard label="Documents signed" value={summary.documentsSigned} icon={<DrawIcon />} />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <StatCard
            label="Valid verifications"
            value={summary.validVerifications}
            icon={<GppGoodIcon />}
            color={verdictPalette.valid.main}
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <StatCard
            label="Tampering detected"
            value={summary.tamperingDetected}
            icon={<GppBadIcon />}
            color={summary.tamperingDetected > 0 ? verdictPalette.invalid.main : undefined}
          />
        </Grid>
      </Grid>

      <Grid container spacing={2}>
        <Grid size={{ xs: 12, md: 7 }}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Verification outcomes
              </Typography>

              {totalVerifications === 0 ? (
                <Typography variant="body2" color="text.secondary" sx={{ py: 6, textAlign: 'center' }}>
                  No verifications recorded yet. Verify a document to populate this chart.
                </Typography>
              ) : (
                <Box sx={{ height: 260 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={verificationData} margin={{ top: 8, right: 8, bottom: 8, left: -20 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke={theme.palette.divider} />
                      <XAxis dataKey="name" stroke={theme.palette.text.secondary} fontSize={12} />
                      <YAxis allowDecimals={false} stroke={theme.palette.text.secondary} fontSize={12} />
                      <ChartTooltip
                        contentStyle={{
                          background: theme.palette.background.paper,
                          border: `1px solid ${theme.palette.divider}`,
                          borderRadius: 8,
                        }}
                      />
                      <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                        {verificationData.map((entry) => (
                          <Cell key={entry.name} fill={entry.fill} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </Box>
              )}

              {successRatio !== null && (
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  {successRatio}% of verifications returned a fully trusted result.
                </Typography>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12, md: 5 }}>
          <Stack spacing={2} sx={{ height: '100%' }}>
            <Card>
              <CardContent>
                <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
                  <LinkIcon color={summary.auditChainIntact ? 'success' : 'error'} />
                  <Typography variant="h6">Audit chain integrity</Typography>
                </Stack>
                <Alert
                  severity={summary.auditChainIntact ? 'success' : 'error'}
                  sx={{ mb: 1 }}
                >
                  {summary.auditChainIntact ? 'Chain verified' : 'Chain broken'}
                </Alert>
                <Typography variant="body2" color="text.secondary">
                  {summary.auditChainExplanation}
                </Typography>
                <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
                  Hash-chained tamper-evident log. Each record's hash covers the previous
                  one, so any retroactive edit breaks every link after it.
                </Typography>
              </CardContent>
            </Card>

            <Card sx={{ flexGrow: 1 }}>
              <CardContent>
                <Typography variant="h6" sx={{ mb: 1 }}>
                  Trust configuration
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {summary.trustAnchors} configured trust anchor
                  {summary.trustAnchors === 1 ? '' : 's'}. Certificates embedded in a
                  submitted document are never treated as trust anchors themselves.
                </Typography>
              </CardContent>
            </Card>
          </Stack>
        </Grid>
      </Grid>

      <Card>
        <CardContent>
          <Typography variant="h6" sx={{ mb: 2 }}>
            Recent activity
          </Typography>
          {summary.recentActivity.length === 0 ? (
            <Typography variant="body2" color="text.secondary">
              No activity recorded yet.
            </Typography>
          ) : (
            <Stack spacing={1.25}>
              {summary.recentActivity.slice(0, 8).map((event) => (
                <Stack
                  key={event.id}
                  direction="row"
                  spacing={2}
                  alignItems="baseline"
                  sx={{ borderBottom: 1, borderColor: 'divider', pb: 1 }}
                >
                  <Typography variant="caption" color="text.secondary" sx={{ minWidth: 150 }}>
                    {new Date(event.timestamp).toLocaleString()}
                  </Typography>
                  <Typography variant="body2" sx={{ fontWeight: 600, minWidth: 190 }}>
                    {event.eventType.replaceAll('_', ' ').toLowerCase()}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {event.details}
                  </Typography>
                </Stack>
              ))}
            </Stack>
          )}
        </CardContent>
      </Card>
    </Stack>
  );
}
