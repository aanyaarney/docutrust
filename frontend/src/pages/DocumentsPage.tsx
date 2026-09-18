import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Card from '@mui/material/Card';
import Checkbox from '@mui/material/Checkbox';
import Chip from '@mui/material/Chip';
import CircularProgress from '@mui/material/CircularProgress';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import FormControlLabel from '@mui/material/FormControlLabel';
import IconButton from '@mui/material/IconButton';
import Skeleton from '@mui/material/Skeleton';
import Snackbar from '@mui/material/Snackbar';
import Stack from '@mui/material/Stack';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import TextField from '@mui/material/TextField';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import DescriptionIcon from '@mui/icons-material/DescriptionOutlined';
import DownloadIcon from '@mui/icons-material/DownloadOutlined';
import DrawIcon from '@mui/icons-material/DrawOutlined';
import HistoryIcon from '@mui/icons-material/HistoryToggleOffOutlined';

import { EmptyState } from '../components/EmptyState';
import { Monospace } from '../components/Monospace';
import { describeError, documentsApi } from '../api/client';
import type { DocumentSummary } from '../api/types';

export function DocumentsPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [signTarget, setSignTarget] = useState<DocumentSummary | null>(null);
  const [reason, setReason] = useState('I approve this document');
  const [location, setLocation] = useState('Bengaluru, IN');
  const [visibleSignature, setVisibleSignature] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const documentsQuery = useQuery({
    queryKey: ['documents'],
    queryFn: documentsApi.list,
  });

  const signMutation = useMutation({
    mutationFn: (target: DocumentSummary) =>
      documentsApi.sign(target.id, { reason, location, visibleSignature }),
    onSuccess: (result) => {
      setSignTarget(null);
      setToast(
        'Signed with ' + result.signatureAlgorithm + ' (' + result.signatureFormat + ').',
      );
      void queryClient.invalidateQueries({ queryKey: ['documents'] });
    },
    onError: (e) => {
      setSignTarget(null);
      setError(describeError(e));
    },
  });

  const handleDownload = async (target: DocumentSummary) => {
    try {
      await documentsApi.download(target.id, target.fileName);
    } catch (e) {
      setError(describeError(e));
    }
  };

  return (
    <Stack spacing={3}>
      <Stack
        direction="row"
        justifyContent="space-between"
        alignItems="center"
        flexWrap="wrap"
        useFlexGap
      >
        <Box>
          <Typography variant="h4" sx={{ mb: 0.5 }}>
            Documents
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Every document you have uploaded, with its digest and signature state.
          </Typography>
        </Box>
        <Button variant="contained" onClick={() => navigate('/upload')}>
          Upload document
        </Button>
      </Stack>

      {error && (
        <Alert severity="error" onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Card>
        {documentsQuery.isLoading && (
          <Box sx={{ p: 3 }}>
            {[0, 1, 2].map((row) => (
              <Skeleton key={row} height={48} />
            ))}
          </Box>
        )}

        {documentsQuery.isError && (
          <Box sx={{ p: 3 }}>
            <Alert severity="error">{describeError(documentsQuery.error)}</Alert>
          </Box>
        )}

        {documentsQuery.data?.length === 0 && (
          <EmptyState
            icon={<DescriptionIcon />}
            title="No documents yet"
            description="Upload your first PDF to digitally sign it and verify its integrity."
            action={
              <Button variant="contained" onClick={() => navigate('/upload')}>
                Upload a PDF
              </Button>
            }
          />
        )}

        {documentsQuery.data && documentsQuery.data.length > 0 && (
          <TableContainer sx={{ overflowX: 'auto' }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Name</TableCell>
                  <TableCell>Uploaded</TableCell>
                  <TableCell align="right">Size</TableCell>
                  <TableCell align="right">Pages</TableCell>
                  <TableCell>SHA-256</TableCell>
                  <TableCell>State</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {documentsQuery.data.map((document) => (
                  <TableRow key={document.id} hover>
                    <TableCell>{document.fileName}</TableCell>
                    <TableCell>{new Date(document.uploadedAt).toLocaleString()}</TableCell>
                    <TableCell align="right">{document.sizeBytes.toLocaleString()}</TableCell>
                    <TableCell align="right">{document.pageCount ?? '-'}</TableCell>
                    <TableCell>
                      <Tooltip title={document.sha256} arrow>
                        <Box>
                          <Monospace>{document.sha256.slice(0, 16)}</Monospace>
                        </Box>
                      </Tooltip>
                    </TableCell>
                    <TableCell>
                      <Chip
                        size="small"
                        label={document.signatureState === 'SIGNED' ? 'Signed' : 'Unsigned'}
                        color={document.signatureState === 'SIGNED' ? 'success' : 'default'}
                        variant={document.signatureState === 'SIGNED' ? 'filled' : 'outlined'}
                      />
                    </TableCell>
                    <TableCell align="right">
                      <Stack direction="row" spacing={0.5} justifyContent="flex-end">
                        <Tooltip title="Sign this document" arrow>
                          <IconButton size="small" onClick={() => setSignTarget(document)}>
                            <DrawIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Download latest version" arrow>
                          <IconButton size="small" onClick={() => handleDownload(document)}>
                            <DownloadIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Audit history" arrow>
                          <IconButton
                            size="small"
                            onClick={() => navigate('/audit?document=' + document.id)}
                          >
                            <HistoryIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </Stack>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Card>

      {/* Signing is consequential and cannot be undone, so it asks first. */}
      <Dialog open={signTarget !== null} onClose={() => setSignTarget(null)} maxWidth="sm" fullWidth>
        <DialogTitle>Sign {signTarget?.fileName}</DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2.5 }}>
            The digital signature cryptographically protects this document. Any
            modification made after signing will invalidate it.
          </Alert>

          <Stack spacing={2}>
            <TextField
              label="Reason for signing"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              fullWidth
              helperText="Recorded inside the signature and covered by it."
            />
            <TextField
              label="Location"
              value={location}
              onChange={(e) => setLocation(e.target.value)}
              fullWidth
            />

            <FormControlLabel
              control={
                <Checkbox
                  checked={visibleSignature}
                  onChange={(e) => setVisibleSignature(e.target.checked)}
                />
              }
              label="Draw a visible signature block on the last page"
            />

            {/*
              Stated plainly at the point of choosing. A visible block is the
              part users instinctively treat as proof, and it is the one part
              that proves nothing.
            */}
            <Typography variant="caption" color="text.secondary">
              The visible block is informational only. It adds nothing to the
              cryptographic guarantee — a forged document can carry an identical
              one. Only verification establishes authenticity.
            </Typography>
          </Stack>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setSignTarget(null)}>Cancel</Button>
          <Button
            variant="contained"
            disabled={signMutation.isPending}
            startIcon={
              signMutation.isPending ? <CircularProgress size={16} color="inherit" /> : <DrawIcon />
            }
            onClick={() => signTarget && signMutation.mutate(signTarget)}
          >
            {signMutation.isPending ? 'Signing' : 'Sign document'}
          </Button>
        </DialogActions>
      </Dialog>

      <Snackbar
        open={toast !== null}
        autoHideDuration={8000}
        onClose={() => setToast(null)}
        message={toast}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      />
    </Stack>
  );
}
