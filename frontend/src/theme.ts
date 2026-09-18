import { createTheme, type Theme } from '@mui/material/styles';

/**
 * DocuTrust theme.
 *
 * The three verdict colours are defined once, here, and used everywhere a
 * verdict is rendered. Green, amber and red carry specific meanings —
 * authentic, cryptographically valid but untrusted, and tampered — and those
 * meanings must look identical on every screen.
 *
 * Colour is never the only signal. Every verdict is shown with an icon and a
 * text label as well, because roughly one in twelve men has a colour vision
 * deficiency, and a red/green distinction alone would be invisible to them
 * (specification section 54).
 */

export const verdictPalette = {
  valid: {
    main: '#1b873f',
    light: '#e7f5ec',
    dark: '#12652d',
    contrastText: '#ffffff',
  },
  untrusted: {
    main: '#b26a00',
    light: '#fdf3e3',
    dark: '#8a5200',
    contrastText: '#ffffff',
  },
  invalid: {
    main: '#c62828',
    light: '#fdeded',
    dark: '#9b1c1c',
    contrastText: '#ffffff',
  },
  neutral: {
    main: '#5b6472',
    light: '#eef1f5',
    dark: '#39414d',
    contrastText: '#ffffff',
  },
} as const;

const sharedTypography = {
  fontFamily: [
    '"Inter"',
    '-apple-system',
    'BlinkMacSystemFont',
    '"Segoe UI"',
    'Roboto',
    '"Helvetica Neue"',
    'Arial',
    'sans-serif',
  ].join(','),
  h4: { fontWeight: 650, letterSpacing: '-0.02em' },
  h5: { fontWeight: 650, letterSpacing: '-0.01em' },
  h6: { fontWeight: 600 },
  subtitle2: { fontWeight: 600, letterSpacing: '0.01em' },
  button: { textTransform: 'none' as const, fontWeight: 600 },
};

/** Monospace stack for hashes, serial numbers and byte ranges. */
export const monospaceFont =
  '"JetBrains Mono", "SF Mono", "Cascadia Mono", Consolas, "Liberation Mono", monospace';

export function buildTheme(mode: 'light' | 'dark'): Theme {
  const isDark = mode === 'dark';

  return createTheme({
    palette: {
      mode,
      primary: { main: isDark ? '#6ea8fe' : '#11397a' },
      secondary: { main: isDark ? '#8ed1c0' : '#0f6e5c' },
      success: verdictPalette.valid,
      warning: verdictPalette.untrusted,
      error: verdictPalette.invalid,
      background: {
        default: isDark ? '#0d1117' : '#f5f7fa',
        paper: isDark ? '#161b22' : '#ffffff',
      },
      divider: isDark ? 'rgba(255,255,255,0.10)' : 'rgba(17,25,40,0.10)',
    },
    typography: sharedTypography,
    shape: { borderRadius: 10 },
    components: {
      MuiCard: {
        defaultProps: { elevation: 0 },
        styleOverrides: {
          root: {
            border: `1px solid ${isDark ? 'rgba(255,255,255,0.10)' : 'rgba(17,25,40,0.10)'}`,
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: { backgroundImage: 'none' },
        },
      },
      MuiButton: {
        defaultProps: { disableElevation: true },
      },
      MuiChip: {
        styleOverrides: {
          root: { fontWeight: 600 },
        },
      },
      MuiTableCell: {
        styleOverrides: {
          head: { fontWeight: 650 },
        },
      },
    },
  });
}
