import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Grid from '@mui/material/Grid';
import LinearProgress from '@mui/material/LinearProgress';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import DescriptionIcon from '@mui/icons-material/DescriptionOutlined';

import { FileDropzone } from '../components/FileDropzone';
import { Monospace } from '../components/Monospace';
import { describeError, documentsApi } from '../api/client';
import type { DocumentSummary } from '../api/types';

/** Upload a PDF, then show exactly what the system recorded about it. */
export function UploadPage() {
  const navigate = useNavigate();
  const [uploaded, setUploaded] = useState<DocumentSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const handleFile = async (file: File) => {
    setBusy(true);
    setError(null);
    setUploaded(null);
    try {
      setUploaded(await documentsApi.upload(file));
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack spacing={3}>
      <Box>
        <Typography variant="h4" sx={{ mb: 0.5 }}>
          Upload a document
        </Typography>
        <Typography variant="body2" color="text.secondary">
          PDFs only. Every upload is checked by its actual file signature rather than the
          content type the browser claims, and its SHA-256 digest is recorded on arrival.
        </Typography>
      </Box>

      <Card>
        <CardContent>
          <FileDropzone onFileSelected={handleFile} disabled={busy} />
          {busy && (
            <Box sx={{ mt: 2 }}>
              <LinearProgress />
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                Uploading and hashing…
              </Typography>
            </Box>
          )}
        </CardContent>
      </Card>

      {error && <Alert severity="error">{error}</Alert>}

      {uploaded && (
        <Card>
          <CardContent>
            <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mb: 2.5 }}>
              <DescriptionIcon color="primary" />
              <Typography variant="h6">{uploaded.fileName}</Typography>
            </Stack>

            <Grid container spacing={2}>
              <Field label="Document ID" value={uploaded.id} mono />
              <Field label="Size" value={`${uploaded.sizeBytes.toLocaleString()} bytes`} />
              <Field label="Pages" value={String(uploaded.pageCount ?? 'Unknown')} />
              <Field label="Uploaded at" value={new Date(uploaded.uploadedAt).toLocaleString()} />
              <Field label="Status" value={uploaded.signatureState} />
              <Field label="SHA-256" value={uploaded.sha256} mono />
            </Grid>

            <Alert severity="info" sx={{ mt: 3 }}>
              This digest identifies the file exactly as uploaded. Signing produces a new
              version with its own digest — the original is never overwritten.
            </Alert>

            <Stack direction="row" spacing={1.5} sx={{ mt: 3 }}>
              <Button variant="contained" onClick={() => navigate('/documents')}>
                Go to documents to sign it
              </Button>
              <Button variant="outlined" onClick={() => setUploaded(null)}>
                Upload another
              </Button>
            </Stack>
          </CardContent>
        </Card>
      )}
    </Stack>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <>
      <Grid size={{ xs: 12, sm: 3 }}>
        <Typography variant="body2" color="text.secondary">
          {label}
        </Typography>
      </Grid>
      <Grid size={{ xs: 12, sm: 9 }}>
        {mono ? <Monospace>{value}</Monospace> : <Typography variant="body2">{value}</Typography>}
      </Grid>
    </>
  );
}
