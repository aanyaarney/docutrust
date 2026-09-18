import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import type { ReactNode } from 'react';

/**
 * Placeholder shown when a collection is empty.
 *
 * Says what the user can do next rather than only stating that nothing is here.
 * An empty screen with the word "None" teaches nobody anything
 * (specification section 67).
 */
export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon: ReactNode;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <Stack alignItems="center" spacing={2} sx={{ py: 8, px: 3, textAlign: 'center' }}>
      <Box sx={{ color: 'text.disabled', '& svg': { fontSize: 56 } }}>{icon}</Box>
      <Typography variant="h6">{title}</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 440 }}>
        {description}
      </Typography>
      {action}
    </Stack>
  );
}
