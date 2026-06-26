import { Card, Text } from '@radix-ui/themes';
import type { ReactNode } from 'react';

type AccentColor = 'green' | 'blue' | 'violet' | 'amber';

export function SummaryCard({
  value,
  label,
  sub,
  accent,
}: {
  value: ReactNode;
  label: string;
  sub?: string;
  accent?: AccentColor;
}) {
  return (
    <Card
      style={{
        textAlign: 'center',
        ...(accent && {
          backgroundColor: `var(--${accent}-2)`,
          boxShadow: `inset 0 0 0 5px var(--${accent}-9)`,
        }),
      }}
    >
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
    </Card>
  );
}
