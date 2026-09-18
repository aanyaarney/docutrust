import { useCallback, useRef, useState, type DragEvent } from 'react';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import CloudUploadIcon from '@mui/icons-material/CloudUploadOutlined';

/**
 * Drag-and-drop file selector.
 *
 * Keyboard accessible: the drop area is a real focusable button that opens the
 * native file picker on Enter or Space. Drag-and-drop alone would exclude
 * anyone navigating by keyboard, and a drop target that only responds to a
 * mouse is not an acceptable sole means of input.
 */
export function FileDropzone({
  onFileSelected,
  accept = 'application/pdf',
  disabled = false,
  label = 'Drop a PDF here',
  hint = 'or click to choose a file',
}: {
  onFileSelected: (file: File) => void;
  accept?: string;
  disabled?: boolean;
  label?: string;
  hint?: string;
}) {
  const [isDragging, setIsDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDrop = useCallback(
    (event: DragEvent<HTMLElement>) => {
      event.preventDefault();
      setIsDragging(false);
      if (disabled) {
        return;
      }
      const file = event.dataTransfer.files?.[0];
      if (file) {
        onFileSelected(file);
      }
    },
    [disabled, onFileSelected],
  );

  return (
    <Box
      component="button"
      type="button"
      disabled={disabled}
      onClick={() => inputRef.current?.click()}
      onDragOver={(e) => {
        e.preventDefault();
        if (!disabled) setIsDragging(true);
      }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={handleDrop}
      aria-label={`${label}. ${hint}`}
      sx={{
        width: '100%',
        cursor: disabled ? 'not-allowed' : 'pointer',
        border: '2px dashed',
        borderColor: isDragging ? 'primary.main' : 'divider',
        bgcolor: isDragging ? 'action.hover' : 'transparent',
        borderRadius: 2,
        p: { xs: 4, md: 6 },
        transition: 'border-color 120ms, background-color 120ms',
        font: 'inherit',
        color: 'inherit',
        opacity: disabled ? 0.6 : 1,
        '&:hover': { borderColor: disabled ? 'divider' : 'primary.main' },
        '&:focus-visible': { outline: '2px solid', outlineColor: 'primary.main', outlineOffset: 2 },
      }}
    >
      <Stack alignItems="center" spacing={1.5}>
        <CloudUploadIcon sx={{ fontSize: 48, color: isDragging ? 'primary.main' : 'text.disabled' }} />
        <Typography variant="h6">{label}</Typography>
        <Typography variant="body2" color="text.secondary">
          {hint}
        </Typography>
      </Stack>

      <input
        ref={inputRef}
        type="file"
        accept={accept}
        hidden
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) {
            onFileSelected(file);
          }
          // Reset so selecting the same file twice still fires a change event.
          e.target.value = '';
        }}
      />
    </Box>
  );
}
