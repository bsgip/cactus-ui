import { Box, Text } from '@radix-ui/themes';
import type { ReactNode } from 'react';

type AccentColor = 'green' | 'blue' | 'cyan' | 'violet' | 'amber';

const BORDER_WIDTH = 4;

export function SummaryCard({
  value,
  label,
  sub,
  icon,
  accent,
}: {
  value: ReactNode;
  label: string;
  sub?: string;
  icon?: ReactNode;
  accent?: AccentColor;
}) {
  return (
    <Box
      p="4"
      style={{
        textAlign: 'center',
        borderRadius: 'var(--radius-4)',
        backgroundColor: 'var(--color-panel-solid)',
        border: `${BORDER_WIDTH}px solid ${accent ? `var(--${accent}-9)` : 'var(--gray-6)'}`,
      }}
    >
      {icon && (
        <Text as="div" size="5" mb="1" style={accent ? { color: `var(--${accent}-9)` } : undefined}>
          {icon}
        </Text>
      )}
      <Text as="div" size="7" weight="bold" style={accent ? { color: `var(--${accent}-11)` } : undefined}>
        {value}
      </Text>
      <Text as="div" size="2" color="gray">
        {label}
      </Text>
      {sub && (
        <Text as="div" size="1" color="gray">
          {sub}
        </Text>
      )}
    </Box>
  );
}
