import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import CancelIcon from '@mui/icons-material/Cancel';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';

import { toneToColor, type StatusPresentation, type Tone } from './verdict';

function iconFor(tone: Tone) {
  switch (tone) {
    case 'valid':
      return <CheckCircleIcon fontSize="small" />;
    case 'untrusted':
      return <WarningAmberIcon fontSize="small" />;
    case 'invalid':
      return <CancelIcon fontSize="small" />;
    default:
      return <HelpOutlineIcon fontSize="small" />;
  }
}

/**
 * A status indicator carrying an icon, a text label and a colour.
 *
 * All three are always present. Colour alone would be unreadable to anyone with
 * a colour vision deficiency, and a red/green pair is the single most common
 * case of that (specification section 54).
 */
export function StatusChip({
  presentation,
  size = 'small',
}: {
  presentation: StatusPresentation;
  size?: 'small' | 'medium';
}) {
  return (
    <Tooltip title={presentation.hint} arrow>
      <Chip
        icon={iconFor(presentation.tone)}
        label={presentation.label}
        color={toneToColor(presentation.tone)}
        size={size}
        variant={presentation.tone === 'neutral' ? 'outlined' : 'filled'}
        aria-label={`${presentation.label}. ${presentation.hint}`}
      />
    </Tooltip>
  );
}
