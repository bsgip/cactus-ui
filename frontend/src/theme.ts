import { createTheme, type CSSVariablesResolver, type MantineColorsTuple } from '@mantine/core';

// Primary action colour (buttons, links). A deeper, less cyan-leaning blue than
// Mantine's default. Shade 6 (#0d6efd) is the primary; shade 7 (#0a58ca) its hover.
const blue: MantineColorsTuple = [
  '#e7f1ff',
  '#cfe2ff',
  '#9ec5fe',
  '#6ea8fe',
  '#3d8bfd',
  '#1763e8',
  '#0d6efd',
  '#0a58ca',
  '#084298',
  '#052c65',
];

// Deep, muted "forest" green for the navbar and green semantics. Lower glare
// than Mantine's default green. The navbar uses shade 8.
const green: MantineColorsTuple = [
  '#f2f8f4',
  '#e2f0e7',
  '#c3ddca',
  '#a1c9ab',
  '#7fb48c',
  '#5da170',
  '#4a9c63',
  '#3f8f59',
  '#348852',
  '#266b41',
];

// A truer, deeper red for failure states. Mantine's default red (#fa5252 at shade 6) reads as
// coral/orange; this leans crimson so "Failed" looks unambiguously red.
const red: MantineColorsTuple = [
  '#fff0f1',
  '#ffdde0',
  '#f9bcc1',
  '#f0959d',
  '#e76a76',
  '#df4856',
  '#d12d3c',
  '#b41f2e',
  '#8c1722',
  '#6a1019',
];

export const theme = createTheme({
  primaryColor: 'blue',
  primaryShade: { light: 6 },
  defaultRadius: 'md',
  colors: { blue, green, red },
  components: {
    // Subtle bordered-card depth so content doesn't sit flat on pure white.
    Card: {
      defaultProps: {
        withBorder: true,
        shadow: 'xs',
      },
    },
    // Mantine badges default to a fully-rounded pill (radius "xl"); soften to a
    // gently-rounded rectangle so count/status badges read less bubbly.
    Badge: {
      defaultProps: {
        radius: 'sm',
      },
    },
  },
});

// Faintly off-white page background so content cards read against it.
export const cssVariablesResolver: CSSVariablesResolver = () => ({
  variables: {},
  light: { '--mantine-color-body': '#fbfcfb' },
  dark: {},
});
