import { useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Chip from '@mui/material/Chip';
import Skeleton from '@mui/material/Skeleton';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import HistoryIcon from '@mui/icons-material/HistoryToggleOffOutlined';

import { dashboardApi, describeError, documentsApi } from '../api/client';
import { EmptyState } from '../components/EmptyState';
import { Monospace } from '../components/Monospace';
import type { AuditRecord } from '../api/types';

/** Colour cue by event kind. Tampering must stand out immediately. */
function toneFor(eventType: string): 'error' | 'success' | 'warning' | 'default' {
  if (eventType === 'TAMPERING_DETECTED') return 'error';
  if (eventType === 'VERIFICATION_FAILED' || eventType === 'AUTHENTICATION_FAILED') return 'warning';
  if (eventType === 'DOCUMENT_SIGNED' || eventType === 'SIGNATURE_VERIFIED') return 'success';
  return 'default';
}

function TimelineEntry({ record, isLast }: { record: AuditRecord; isLast: boolean }) {
  return (
    <Stack direction="row" spacing={2}>
      {/* Chain rail: a visual echo of the hash linking each record to the last. */}
      <Stack alignItems="center" sx={{ width: 24, flexShrink: 0 }}>
        <Box
          sx={{
            width: 12,
            height: 12,
            borderRadius: '50%',
            bgcolor: toneFor(record.eventType) === 'default' ? 'text.disabled' : `${toneFor(record.eventType)}.main`,
            mt: 0.75,
          }}
        />
        {!isLast && <Box sx={{ width: 2, flexGrow: 1, bgcolor: 'divider', my: 0.5 }} />}
      </Stack>

      <Box sx={{ pb: 3, minWidth: 0, flexGrow: 1 }}>
        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
          <Chip
            size="small"
            label={record.eventType.replaceAll('_', ' ').toLowerCase()}
            color={toneFor(record.eventType)}
            variant={toneFor(record.eventType) === 'default' ? 'outlined' : 'filled'}
          />
          <Typography variant="caption" color="text.secondary">
            #{record.sequence} · {new Date(record.timestamp).toLocaleString()}
          </Typography>
        </Stack>

        {record.details && (
          <Typography variant="body2" sx={{ mt: 0.75 }}>
            {record.details}
          </Typography>
        )}

        <Box sx={{ mt: 0.75 }}>
          <Typography variant="caption" color="text.secondary" display="block">
            record hash
          </Typography>
          <Monospace sx={{ fontSize: '0.72rem', color: 'text.secondary' }}>
            {record.recordHash}
          </Monospace>
        </Box>
      </Box>
    </Stack>
  );
}

export function AuditPage() {
  const [searchParams] = useSearchParams();
  const documentId = searchParams.get('document');

  const summaryQuery = useQuery({
    queryKey: ['dashboard'],
    queryFn: dashboardApi.summary,
  });

  const documentAuditQuery = useQuery({
    queryKey: ['audit', documentId],
    queryFn: () => documentsApi.audit(documentId as string),
    enabled: documentId !== null,
  });

  const records: AuditRecord[] = documentId
    ? (documentAuditQuery.data ?? [])
    : (summaryQuery.data?.recentActivity ?? []).slice().reverse();

  const loading = documentId ? documentAuditQuery.isLoading : summaryQuery.isLoading;
  const error = documentId ? documentAuditQuery.error : summaryQuery.error;

  return (
    <Stack spacing={3}>
      <Box>
        <Typography variant="h4" sx={{ mb: 0.5 }}>
          Audit trail
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {documentId
            ? 'Every recorded event for this document, in chain order.'
            : 'Recent activity across the system, in chain order.'}
        </Typography>
      </Box>

      {summaryQuery.data && (
        <Alert severity={summaryQuery.data.auditChainIntact ? 'success' : 'error'}>
          <strong>
            {summaryQuery.data.auditChainIntact ? 'Audit chain intact' : 'Audit chain broken'}
          </strong>{' '}
          — {summaryQuery.data.auditChainExplanation}
        </Alert>
      )}

      <Card>
        <CardContent>
          <Typography variant="body2" color="text.secondary">
            Each record's hash is computed over the previous record's hash together with
            its own contents. Editing, inserting or deleting any entry breaks every link
            that follows, which is what makes the log tamper-evident. It is not a
            blockchain: there is no distributed consensus, so an attacker with full
            database write access could recompute the chain. It raises the cost of
            undetected tampering rather than making it impossible.
          </Typography>
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          {loading && (
            <Stack spacing={2}>
              {[0, 1, 2].map((i) => (
                <Skeleton key={i} height={64} />
              ))}
            </Stack>
          )}

          {error && <Alert severity="error">{describeError(error)}</Alert>}

          {!loading && !error && records.length === 0 && (
            <EmptyState
              icon={<HistoryIcon />}
              title="No audit events yet"
              description="Upload, sign or verify a document and its history will appear here."
            />
          )}

          {records.length > 0 && (
            <Box sx={{ pt: 1 }}>
              {records.map((record, index) => (
                <TimelineEntry
                  key={record.id}
                  record={record}
                  isLast={index === records.length - 1}
                />
              ))}
            </Box>
          )}
        </CardContent>
      </Card>
    </Stack>
  );
}
