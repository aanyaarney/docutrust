import Box from '@mui/material/Box';
import type { SxProps, Theme } from '@mui/material/styles';

import { monospaceFont } from '../theme';

/**
 * Renders technical values — hashes, serial numbers, byte ranges — in a
 * monospace face that breaks anywhere.
 *
 * A 64-character SHA-256 digest has no natural break points, so without
 * explicit wrapping it either overflows its container or forces the page to
 * scroll sideways.
 */
export function Monospace({
  children,
  sx,
}: {
  children: React.ReactNode;
  sx?: SxProps<Theme>;
}) {
  return (
    <Box
      component="span"
      sx={{
        fontFamily: monospaceFont,
        fontSize: '0.8125rem',
        wordBreak: 'break-all',
        ...sx,
      }}
    >
      {children}
    </Box>
  );
}
