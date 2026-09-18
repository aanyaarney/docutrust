import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';

import { StatusChip } from './StatusChip';
import type { StatusPresentation } from './verdict';

/**
 * One independent verification check, presented on its own card.
 *
 * Each check gets equal visual weight because each answers a different
 * question. A tampered document, for instance, has a failed integrity check and
 * a perfectly valid certificate — showing them side by side is what makes that
 * distinction legible instead of confusing.
 */
export function CheckCard({
  title,
  presentation,
  explanation,
}: {
  title: string;
  presentation: StatusPresentation;
  explanation?: string;
}) {
  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Stack direction="row" alignItems="center" spacing={0.5} sx={{ mb: 1.5 }}>
          <Typography variant="subtitle2" color="text.secondary">
            {title}
          </Typography>
          <Tooltip title={presentation.hint} arrow>
            <InfoOutlinedIcon sx={{ fontSize: 15, color: 'text.disabled' }} />
          </Tooltip>
        </Stack>

        <StatusChip presentation={presentation} size="medium" />

        {explanation && (
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1.5, lineHeight: 1.5 }}>
            {explanation}
          </Typography>
        )}
      </CardContent>
    </Card>
  );
}
